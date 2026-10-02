
import os
import csv
import re
import sqlite3
import hashlib
import secrets
import unicodedata
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Form, File, UploadFile
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.templating import Jinja2Templates
from dotenv import load_dotenv
from openai import OpenAI


# ============================================================
# 1. 기본 설정
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

STATIC_DIR = BASE_DIR / "static"
TEMPLATE_DIR = BASE_DIR / "templates"
PROFILE_DIR = STATIC_DIR / "profiles"

STATIC_DIR.mkdir(parents=True, exist_ok=True)
PROFILE_DIR.mkdir(parents=True, exist_ok=True)

load_dotenv(BASE_DIR / ".env")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()

SECRET_KEY = os.getenv(
    "SESSION_SECRET",
    "dori-fit-secret-key-change-this"
)

client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

templates = Jinja2Templates(directory=str(TEMPLATE_DIR))

DB_PATH = BASE_DIR / "members.db"


# ============================================================
# 2. CSV 파일 자동 탐색
# ============================================================

def find_csv_file():

    print("\n" + "=" * 60)
    print("[CSV 파일 탐색 시작]")

    print("현재 실행 중인 main.py:", Path(__file__).resolve())
    print("프로젝트 폴더:", BASE_DIR)
    print("static 폴더:", STATIC_DIR)
    print("static 폴더 존재 여부:", STATIC_DIR.exists())

    if not STATIC_DIR.exists():

        print("오류: static 폴더가 없습니다.")
        return None

    # static 폴더 및 하위 폴더의 모든 파일 검색
    all_files = list(STATIC_DIR.rglob("*"))

    print("\n[static 폴더 내부 파일 목록]")

    for file in all_files:

        if file.is_file():
            print("파일:", file.name)
            print("경로:", file.resolve())

    # 확장자가 CSV인 파일 탐색
    csv_files = [
        file for file in all_files
        if file.is_file() and file.suffix.lower() == ".csv"
    ]

    # 확장자가 숨겨지거나 이름이 이상한 경우를 위한 추가 탐색
    if not csv_files:

        csv_files = [
            file for file in all_files
            if file.is_file()
            and "예금목록" in file.name
        ]

    print("\n[발견된 CSV 파일]")

    for file in csv_files:
        print(file.resolve())

    if not csv_files:

        print("CSV 파일을 찾을 수 없습니다.")

        return None

    # 예금목록이라는 이름을 가진 파일 우선
    for file in csv_files:

        if "예금목록" in file.stem:

            print("\n선택된 파일:", file.resolve())
            print("=" * 60)

            return file.resolve()

    # 예금목록이 없다면 첫 번째 CSV 선택
    selected = csv_files[0].resolve()

    print("\n예금목록 파일이 없어 첫 번째 CSV를 사용합니다.")
    print("선택된 파일:", selected)

    print("=" * 60)

    return selected


CSV_PATH = find_csv_file()


# ============================================================
# 3. 데이터베이스 설정
# ============================================================

def get_db():

    conn = sqlite3.connect(DB_PATH)

    conn.row_factory = sqlite3.Row

    return conn


def init_db():

    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS members (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            userid TEXT UNIQUE NOT NULL,

            password TEXT NOT NULL,

            name TEXT NOT NULL,

            email TEXT NOT NULL,

            gender TEXT,

            risk TEXT,

            job TEXT,

            income TEXT,

            age INTEGER,

            profile TEXT

        )
    """)

    conn.commit()
    conn.close()

    print("회원 데이터베이스 초기화 완료")


# ============================================================
# 4. 비밀번호 암호화
# ============================================================

def hash_password(password):

    salt = secrets.token_hex(16)

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100000
    ).hex()

    return salt + "$" + hashed


def verify_password(password, stored):

    try:

        salt, hashed = stored.split("$")

        check = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            100000
        ).hex()

        return secrets.compare_digest(check, hashed)

    except Exception:

        return False


# ============================================================
# 5. CSV 컬럼명 정규화
# ============================================================

def normalize_column(value):

    if value is None:
        return ""

    value = unicodedata.normalize("NFKC", str(value))

    value = value.lower().strip()

    value = re.sub(
        r"[\s_\-()（）\[\]{}%:·]",
        "",
        value
    )

    return value


# ============================================================
# 6. CSV 컬럼 자동 탐색
# ============================================================

def find_column(row, candidates):

    normalized = {
        normalize_column(key): key
        for key in row.keys()
        if key is not None
    }

    # 정확히 일치하는 컬럼 우선
    for candidate in candidates:

        candidate = normalize_column(candidate)

        if candidate in normalized:

            return normalized[candidate]

    # 부분 일치 검색
    for key, original in normalized.items():

        for candidate in candidates:

            candidate = normalize_column(candidate)

            if candidate and candidate in key:

                return original

    return None


def get_value(row, candidates, default=""):

    column = find_column(row, candidates)

    if column is None:
        return default

    value = row.get(column)

    if value is None:
        return default

    return str(value).strip()


# ============================================================
# 7. 금리 숫자 추출
# ============================================================

def extract_rate(value):

    if not value:
        return 0.0

    text = str(value).replace(",", "")

    match = re.search(
        r"\d+(?:\.\d+)?",
        text
    )

    if match:

        try:
            return float(match.group())

        except ValueError:
            return 0.0

    return 0.0


# ============================================================
# 8. CSV 인코딩 자동 처리
# ============================================================

def open_csv_file():

    if CSV_PATH is None:

        raise FileNotFoundError(
            "CSV 파일 경로가 설정되지 않았습니다."
        )

    encodings = [
        "utf-8-sig",
        "utf-8",
        "cp949",
        "euc-kr"
    ]

    last_error = None

    for encoding in encodings:

        try:

            f = open(
                CSV_PATH,
                "r",
                encoding=encoding,
                newline=""
            )

            f.read(2048)
            f.seek(0)

            print("CSV 인코딩:", encoding)

            return f

        except UnicodeDecodeError as e:

            last_error = e

    raise ValueError(
        f"CSV 인코딩 오류: {last_error}"
    )


# ============================================================
# 9. 금융상품 CSV 읽기
# ============================================================

def load_products():

    print("\n" + "=" * 60)
    print("[금융상품 CSV 로딩]")

    if CSV_PATH is None:

        print("CSV 경로가 설정되지 않았습니다.")

        return []

    if not CSV_PATH.exists():

        print("CSV 파일이 존재하지 않습니다.")
        print("경로:", CSV_PATH)

        return []

    products = []

    try:

        with open_csv_file() as f:

            reader = csv.DictReader(f)

            print("CSV 컬럼명:", reader.fieldnames)

            if not reader.fieldnames:

                print("CSV 헤더를 찾을 수 없습니다.")

                return []

            for index, row in enumerate(reader, start=1):

                if not row or not any(row.values()):
                    continue

                # 금융사
                bank = get_value(
                    row,
                    [
                        "금융사",
                        "은행명",
                        "은행",
                        "금융회사",
                        "회사명",
                        "금융기관",
                        "제공기관"
                    ],
                    "금융사 정보 없음"
                )

                # 상품명
                name = get_value(
                    row,
                    [
                        "상품명",
                        "금융상품명",
                        "예금상품명",
                        "상품",
                        "상품이름",
                        "예금명"
                    ],
                    ""
                )

                if not name:
                    print(f"{index}번째 행: 상품명 없음")
                    continue

                # 최고금리
                max_rate_text = get_value(
                    row,
                    [
                        "최고금리",
                        "최고금리(%)",
                        "최고우대금리",
                        "최대금리",
                        "우대금리",
                        "금리"
                    ],
                    "0"
                )

                # 기본금리
                base_rate_text = get_value(
                    row,
                    [
                        "기본금리",
                        "기본금리(%)",
                        "기본이율",
                        "기본금리율"
                    ],
                    "0"
                )

                # 가입기간
                period = get_value(
                    row,
                    [
                        "가입기간",
                        "계약기간",
                        "예치기간",
                        "저축기간",
                        "기간"
                    ],
                    "정보 없음"
                )

                # 가입금액
                amount = get_value(
                    row,
                    [
                        "가입금액",
                        "가입한도",
                        "가입금액한도",
                        "월납입금액",
                        "납입금액",
                        "가입한도금액"
                    ],
                    "정보 없음"
                )

                # 가입방법
                method = get_value(
                    row,
                    [
                        "가입방법",
                        "가입경로",
                        "가입채널",
                        "가입방식",
                        "판매채널"
                    ],
                    "정보 없음"
                )

                # 가입대상
                target = get_value(
                    row,
                    [
                        "가입대상",
                        "가입자격",
                        "가입조건",
                        "대상",
                        "가입대상조건"
                    ],
                    "정보 없음"
                )

                # 상세 URL
                url = get_value(
                    row,
                    [
                        "상세URL",
                        "상품URL",
                        "URL",
                        "링크",
                        "상세링크",
                        "상품상세URL",
                        "가입URL"
                    ],
                    ""
                )

                # 상세정보
                detail = get_value(
                    row,
                    [
                        "상세정보전체",
                        "상세정보",
                        "상품설명",
                        "상품내용",
                        "설명",
                        "특징",
                        "우대조건"
                    ],
                    ""
                )

                product = {

                    "bank": bank,

                    "name": name,

                    "max_rate": max_rate_text,

                    "base_rate": base_rate_text,

                    "rate_num": extract_rate(max_rate_text),

                    "base_rate_num": extract_rate(base_rate_text),

                    "period": period,

                    "amount": amount,

                    "method": method,

                    "target": target,

                    "url": url,

                    "detail": detail

                }

                products.append(product)

        print("\nCSV 로딩 완료")

        print("총 상품 수:", len(products))

        if products:

            print("\n[첫 번째 상품]")

            print(products[0])

        else:

            print("상품 데이터가 없습니다.")
            print("CSV 컬럼명을 확인해주세요.")

        print("=" * 60)

        return products

    except Exception as e:

        print("CSV 로딩 오류:", repr(e))

        return []


# ============================================================
# 10. 맞춤형 상품 추천
# ============================================================

def recommend_products(member):

    products = load_products()

    if not products:
        return []

    age = member["age"] or 25

    risk = member["risk"] or "안정형"

    job = member["job"] or ""

    income = member["income"] or ""

    scored = []

    for p in products:

        score = p["rate_num"]

        # 투자성향
        if risk == "안정형":
            score += 0.3

        elif risk == "안정추구형":
            score += 0.25

        elif risk == "위험중립형":
            score += 0.2

        elif risk == "적극투자형":
            score += 0.15

        elif risk == "공격투자형":
            score += 0.1

        # 나이
        if age < 30:

            if "온라인" in p["method"]:
                score += 0.2

            if "청년" in p["target"]:
                score += 0.5

        elif age >= 50:

            if "연금" in p["name"]:
                score += 0.5

        # 직업
        if job == "자영업":

            if "사업자" in p["target"]:
                score += 0.5

        elif job == "학생":

            if "청년" in p["target"]:
                score += 0.3

        # 소득
        if income == "7,000만원 이상":

            if "고액" in p["amount"]:
                score += 0.2

        scored.append((score, p))

    scored.sort(
        key=lambda x: x[0],
        reverse=True
    )

    result = []

    used = set()

    for score, p in scored:

        key = (
            p["bank"],
            p["name"]
        )

        if key in used:
            continue

        used.add(key)

        result.append(p)

        if len(result) == 3:
            break

    print("\n추천상품 개수:", len(result))

    return result


# ============================================================
# 11. FastAPI 생명주기
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):

    init_db()

    print("\n서버 시작")

    products = load_products()

    print("초기 상품 수:", len(products))

    yield

    print("서버 종료")


app = FastAPI(lifespan=lifespan)


# ============================================================
# 12. 세션 설정
# ============================================================

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    same_site="lax",
    https_only=False
)


# ============================================================
# 13. 정적 파일 설정
# ============================================================

app.mount(
    "/static",
    StaticFiles(directory=str(STATIC_DIR)),
    name="static"
)


# ============================================================
# 14. 로그인 회원 확인
# ============================================================

def current_member(request: Request):

    userid = request.session.get("userid")

    if not userid:
        return None

    conn = get_db()

    member = conn.execute(
        """
        SELECT *
        FROM members
        WHERE userid = ?
        """,
        (userid,)
    ).fetchone()

    conn.close()

    return member


# ============================================================
# 15. 로그인 페이지
# ============================================================

@app.get("/")
async def login_page(request: Request):

    if current_member(request):

        return RedirectResponse(
            "/main",
            status_code=303
        )

    return templates.TemplateResponse(
        request=request,
        name="sign.html",
        context={
            "error": ""
        }
    )


# ============================================================
# 16. 로그인 처리
# ============================================================

@app.post("/login")
async def login(
    request: Request,
    userid: str = Form(...),
    password: str = Form(...)
):

    conn = get_db()

    member = conn.execute(
        """
        SELECT *
        FROM members
        WHERE userid = ?
        """,
        (userid,)
    ).fetchone()

    conn.close()

    if not member or not verify_password(
        password,
        member["password"]
    ):

        return templates.TemplateResponse(
            request=request,
            name="sign.html",
            context={
                "error": "아이디 또는 비밀번호를 확인해주세요."
            },
            status_code=401
        )

    request.session.clear()

    request.session["userid"] = userid

    return RedirectResponse(
        "/main",
        status_code=303
    )


# ============================================================
# 17. 로그아웃
# ============================================================

@app.get("/logout")
async def logout(request: Request):

    request.session.clear()

    return RedirectResponse(
        "/",
        status_code=303
    )


# ============================================================
# 18. 회원가입 페이지
# ============================================================

@app.get("/signup")
async def signup_page(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="signup.html",
        context={
            "error": ""
        }
    )


# ============================================================
# 19. 회원가입 처리
# ============================================================

@app.post("/signup")
async def signup(

    request: Request,

    userid: str = Form(...),

    password: str = Form(...),

    name: str = Form(...),

    email: str = Form(...),

    gender: str = Form(...),

    risk: str = Form(...),

    job: str = Form(...),

    income: str = Form(...),

    age: int = Form(...),

    profile: UploadFile = File(None)

):

    if age < 18 or age > 100:

        return templates.TemplateResponse(
            request=request,
            name="signup.html",
            context={
                "error": "나이를 확인해주세요."
            },
            status_code=400
        )

    if len(password) < 6:

        return templates.TemplateResponse(
            request=request,
            name="signup.html",
            context={
                "error": "비밀번호는 6자 이상이어야 합니다."
            },
            status_code=400
        )

    profile_path = "/static/logo.png"

    if profile and profile.filename:

        ext = Path(profile.filename).suffix.lower()

        if ext not in [".png", ".jpg", ".jpeg", ".webp"]:

            return templates.TemplateResponse(
                request=request,
                name="signup.html",
                context={
                    "error": "PNG, JPG, WEBP 이미지만 가능합니다."
                },
                status_code=400
            )

        content = await profile.read()

        if len(content) > 5 * 1024 * 1024:

            return templates.TemplateResponse(
                request=request,
                name="signup.html",
                context={
                    "error": "프로필 사진은 5MB 이하로 등록해주세요."
                },
                status_code=400
            )

        filename = secrets.token_hex(12) + ext

        destination = PROFILE_DIR / filename

        destination.write_bytes(content)

        profile_path = f"/static/profiles/{filename}"

    conn = get_db()

    try:

        conn.execute(
            """
            INSERT INTO members (
                userid,
                password,
                name,
                email,
                gender,
                risk,
                job,
                income,
                age,
                profile
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                userid,
                hash_password(password),
                name,
                email,
                gender,
                risk,
                job,
                income,
                age,
                profile_path
            )
        )

        conn.commit()

    except sqlite3.IntegrityError:

        conn.close()

        return templates.TemplateResponse(
            request=request,
            name="signup.html",
            context={
                "error": "이미 사용 중인 아이디입니다."
            },
            status_code=400
        )

    conn.close()

    return RedirectResponse(
        "/",
        status_code=303
    )


# ============================================================
# 20. 메인 페이지
# ============================================================

@app.get("/main")
async def main_page(request: Request):

    member = current_member(request)

    if not member:

        return RedirectResponse(
            "/",
            status_code=303
        )

    recommendations = recommend_products(member)

    return templates.TemplateResponse(
        request=request,
        name="main.html",
        context={
            "member": member,
            "products": recommendations
        }
    )


# ============================================================
# 21. 챗봇 페이지
# ============================================================

@app.get("/chatbot")
async def chatbot_page(request: Request):

    member = current_member(request)

    if not member:

        return RedirectResponse(
            "/",
            status_code=303
        )

    return templates.TemplateResponse(
        request=request,
        name="chatbot.html",
        context={
            "member": member
        }
    )


# ============================================================
# 22. 챗봇 API
# ============================================================

@app.post("/chat")
async def chat(request: Request):

    member = current_member(request)

    if not member:

        return JSONResponse(
            {
                "answer": "로그인이 필요합니다."
            },
            status_code=401
        )

    data = await request.json()

    message = str(
        data.get("message", "")
    ).strip()

    if not message:

        return JSONResponse({
            "answer": "질문을 입력해주세요."
        })

    if not client:

        return JSONResponse({
            "answer": "OpenAI API 키가 설정되지 않았습니다. .env 파일을 확인해주세요."
        })

    products = load_products()

    product_context = "\n".join([

        (
            f"금융사: {p['bank']} / "
            f"상품명: {p['name']} / "
            f"최고금리: {p['max_rate']} / "
            f"기본금리: {p['base_rate']} / "
            f"가입기간: {p['period']} / "
            f"가입대상: {p['target']} / "
            f"상세정보: {p['detail']} / "
            f"URL: {p['url']}"
        )

        for p in products[:100]

    ])

    system_prompt = f"""
당신은 하나은행 테마의 금융상품 전문 AI 상담사입니다.

친절하고 전문적인 한국어를 사용하세요.

[회원 정보]

이름: {member['name']}
나이: {member['age']}
투자성향: {member['risk']}
직업: {member['job']}
소득: {member['income']}

[금융상품 데이터]

{product_context}

[상담 원칙]

1. 제공된 CSV 상품 데이터에 근거하여 답변합니다.
2. 존재하지 않는 상품이나 금리를 만들어내지 않습니다.
3. 최고금리와 기본금리를 구분합니다.
4. 가입 조건과 유의사항을 설명합니다.
5. 회원의 연령, 투자성향, 직업, 소득을 고려합니다.
6. 상품 가입을 강요하지 않습니다.
7. 금리 및 가입 조건은 변경될 수 있음을 안내합니다.
8. 실제 가입 전 금융회사에서 최신 조건을 확인하도록 안내합니다.
"""

    try:

        response = client.chat.completions.create(

            model="gpt-4o-mini",

            messages=[
                {
                    "role": "system",
                    "content": system_prompt
                },
                {
                    "role": "user",
                    "content": message
                }
            ],

            temperature=0.5

        )

        answer = response.choices[0].message.content

        return JSONResponse({
            "answer": answer
        })

    except Exception as e:

        print("OpenAI API 오류:", repr(e))

        return JSONResponse(
            {
                "answer": "현재 AI 상담 연결에 문제가 발생했습니다. API 키와 인터넷 연결을 확인해주세요."
            },
            status_code=500
        )


# ============================================================
# 23. CSV 진단 페이지
# ============================================================

@app.get("/check-products")
async def check_products(request: Request):

    member = current_member(request)

    if not member:

        return RedirectResponse(
            "/",
            status_code=303
        )

    products = load_products()

    return JSONResponse({

        "csv_path": str(CSV_PATH) if CSV_PATH else None,

        "file_exists": (
            CSV_PATH.exists()
            if CSV_PATH
            else False
        ),

        "product_count": len(products),

        "products": products[:3]

    })


# ============================================================
# 24. 서버 실행
# ============================================================

if __name__ == "__main__":

    import uvicorn

    print("\n" + "=" * 60)
    print("DoriFit 금융상품 추천 사이트")
    print("=" * 60)

    print("실행 주소: http://localhost")
    print("프로젝트 위치:", BASE_DIR)

    print("CSV 경로:", CSV_PATH)

    print(
        "OpenAI API KEY 설정 여부:",
        bool(OPENAI_API_KEY)
    )

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=80,
        reload=False
    )