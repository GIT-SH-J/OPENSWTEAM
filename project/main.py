import torch
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
from urllib.parse import urlparse, unquote, parse_qs
import csv
from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import os
import io

# PE/SH 파일 분석을 위한 새로운 라이브러리
import pefile
import bashlex
import re
import base64
import sys

# decoder/base64_decoder.py 에서 함수를 임포트합니다.
# sys.path.append를 사용하면 프로젝트 루트 디렉토리에서 실행 시에도
# 'decoder' 패키지를 찾을 수 있도록 돕습니다.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '.'))) # 현재 디렉토리를 path에 추가

try:
    # 이 임포트 문은 'your_project_folder/decoder/base64_decoder.py' 에 해당 함수들이 있을 때 유효합니다.
    from decoder.base64_decoder import find_base64_block, decode_base64_string, decode_obfuscated_url_preserve_query
except ImportError as e:
    print(f"디코더 모듈 임포트 오류: {e}")
    print("'decoder/base64_decoder.py' 파일이 존재하며 'find_base64_block', 'decode_base64_string', 'decode_obfuscated_url_preserve_query' 함수를 포함하는지 확인해주세요.")
    # 임시 더미 함수. 실제 환경에서는 실제 디코더 함수를 구현하거나 에러 처리 필요.
    def find_base64_block(text: str) -> str:
        match = re.search(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', text)
        return match.group(0) if match else ""
    def decode_base64_string(b64_str: str) -> str:
        try:
            return base64.b64decode(b64_str + '==').decode('utf-8', errors='ignore') # 패딩 보정
        except Exception:
            return ""
    def decode_obfuscated_url_preserve_query(url: str) -> str:
        try:
            # 기본 URL 인코딩 해제
            decoded_url = unquote(url)
            
            # Base64 패턴을 찾아 디코딩 시도 (재귀적으로 처리할 수도 있음)
            b64_block = find_base64_block(decoded_url)
            if b64_block:
                base64_decoded = decode_base64_string(b64_block)
                # Base64 디코딩 결과가 유효한 URL 형태라면, 해당 URL을 반환
                if base64_decoded and (base64_decoded.startswith('http://') or base64_decoded.startswith('https://')):
                    return base64_decoded
            return decoded_url
        except Exception:
            return url

app = FastAPI()

# CORS 설정 (이전과 동일)
origins = [
    "http://localhost",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://127.0.0.1:5500", # VS Code Live Server를 사용하는 경우
    "null"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 장치 설정 (이전과 동일)
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print("실행 장치:", device)

# 모델과 토크나이저 불러오기 (이전과 동일)
model = None
tokenizer = None
model_path = "saved_model"
if os.path.exists(model_path):
    try:
        model = DistilBertForSequenceClassification.from_pretrained(model_path).to(device)
        tokenizer = DistilBertTokenizerFast.from_pretrained(model_path)
        print("모델과 토크나이저 로드 완료.")
    except Exception as e:
        print(f"모델 또는 토크나이저 로드 실패: {e}")
        print(f"'{model_path}' 디렉토리가 '{os.getcwd()}'에 있는지, 그리고 유효한 모델 파일인지 확인하세요.")
else:
    print(f"오류: '{model_path}' 디렉토리를 찾을 수 없습니다. 모델을 로드할 수 없습니다.")

# Majestic Million에서 안전 도메인 로딩 (이전과 동일)
safe_domains = set()
majestic_path = "majestic_million.csv"
if os.path.exists(majestic_path):
    try:
        with open(majestic_path, newline='', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader)
            for row in reader:
                if len(row) > 2:
                    domain = row[2].strip().lower()
                    if domain:
                        safe_domains.add(domain)
        print(f"안전 도메인 {len(safe_domains)}개 로드 완료.")
    except Exception as e:
        print(f"majestic_million.csv 로드 중 오류 발생: {e}")
else:
    print(f"오류: '{majestic_path}' 파일을 찾을 수 없습니다. 안전 도메인을 로드할 수 없습니다.")

# URL 정규화 및 도메인 추출 함수 (이전과 동일)
def get_domain(url):
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc
        if netloc.startswith("www."):
            netloc = netloc[4:]
        return netloc.lower()
    except Exception:
        return ""

# === 핵심 URL 예측 로직 함수 (수정됨) ===
def process_single_url(url: str):
    if model is None or tokenizer is None:
        return {"success": False, "message": "모델 또는 토크나이저가 로드되지 않았습니다."}

    norm_url = url.strip()
    if not norm_url:
        return {"success": True, "label_str": "알 수 없음", "confidence": 0.0, "original_url": url, "decoded_url": "빈 URL"}

    decoded_url_for_analysis = norm_url

    try:
        # 1. 일단 전체 URL에 대해 decode_obfuscated_url_preserve_query를 시도합니다.
        #    이는 URL 자체에 URL 인코딩/Base64 인코딩이 되어있을 수 있기 때문입니다.
        temp_decoded_url = decode_obfuscated_url_preserve_query(norm_url)
        
        # 2. 쿼리 파라미터에서 'url' 또는 유사한 이름의 파라미터를 찾아 디코딩을 시도합니다.
        parsed_url = urlparse(temp_decoded_url)
        query_params = parse_qs(parsed_url.query)

        target_param_keys = ['url', 'redirect', 'target', 'link', 'data'] # 탐색할 파라미터 키
        found_obfuscated_param = False

        for key in target_param_keys:
            if key in query_params:
                # 리스트 형태로 반환되므로 첫 번째 값만 사용
                param_value = query_params[key][0] 
                
                # 파라미터 값에 대해 다시 난독화 해제 시도
                decoded_param_value = decode_obfuscated_url_preserve_query(param_value)
                
                # 디코딩된 값이 유효한 URL처럼 보인다면, 이 URL을 최종 분석 대상으로 사용
                if decoded_param_value and (decoded_param_value.startswith('http://') or decoded_param_value.startswith('https://')):
                    decoded_url_for_analysis = decoded_param_value
                    found_obfuscated_param = True
                    break # 찾았으면 더 이상 다른 파라미터를 찾지 않음
        
        # 쿼리 파라미터에서 난독화된 URL을 찾지 못했고,
        # 원래 URL이 완전한 스키마를 가지고 있다면, 최초의 디코딩된 URL (temp_decoded_url)을 사용
        if not found_obfuscated_param:
             decoded_url_for_analysis = temp_decoded_url

    except Exception as e:
        print(f"URL 파싱/디코딩 오류 for '{norm_url}': {e}")
        decoded_url_for_analysis = norm_url # 오류 발생 시 원본 사용

    domain = get_domain(decoded_url_for_analysis)

    if domain and domain in safe_domains:
        return {"success": True, "label_str": "🟢 안전 (도메인 신뢰 기반)", "confidence": 1.0, "original_url": url, "decoded_url": decoded_url_for_analysis}

    model.eval()
    inputs = tokenizer(decoded_url_for_analysis, return_tensors="pt", truncation=True, padding="max_length", max_length=128)
    inputs = {k: v.to(device) for k, v in inputs.items()}

    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=1).squeeze()
        label = torch.argmax(probs).item()
        confidence = probs[label].item()

        if label == 0 and confidence < 0.85:
            label = 1

        label_map = {0: "🔴 위험", 1: "🟡 주의", 2: "🟢 안전"}
        label_str = label_map.get(label, "알 수 없음")

        return {"success": True, "label_str": label_str, "confidence": confidence, "original_url": url, "decoded_url": decoded_url_for_analysis}

# 요청 바디를 위한 Pydantic 모델 정의 (이전과 동일)
class URLRequest(BaseModel):
    url: str

# 단일 URL 예측 API 엔드포인트 (이전과 동일)
@app.post("/predict")
async def predict_url_api(request: URLRequest):
    result = process_single_url(request.url)
    if not result["success"] and result["message"] == "모델 또는 토크나이저가 로드되지 않았습니다.":
        raise HTTPException(status_code=500, detail=result["message"])
    return result

# PE 파일 분석 함수 (이전과 동일)
def analyze_pe_file(file_content_bytes: bytes):
    extracted_urls = []
    pe_header_info = {}
    extracted_strings = []

    try:
        pe = pefile.PE(data=file_content_bytes)

        pe_header_info = {
            "Machine": hex(pe.FILE_HEADER.Machine),
            "NumberOfSections": pe.FILE_HEADER.NumberOfSections,
            "TimeDateStamp": pe.FILE_HEADER.TimeDateStamp,
            "Characteristics": hex(pe.FILE_HEADER.Characteristics),
            "Subsystem": hex(pe.OPTIONAL_HEADER.Subsystem),
            "DllCharacteristics": hex(pe.OPTIONAL_HEADER.DllCharacteristics),
            "ImageBase": hex(pe.OPTIONAL_HEADER.ImageBase),
            "EntryPoint": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        }

        for section in pe.sections:
            try:
                data = section.get_data()
                ascii_strings = re.findall(rb'[ -~]{5,}', data)
                decoded_ascii_strings = [s.decode(errors='ignore') for s in ascii_strings]
                extracted_strings.extend(decoded_ascii_strings)

                for s in decoded_ascii_strings:
                    b64_str = find_base64_block(s)
                    if b64_str:
                        decoded_val = decode_base64_string(b64_str)
                        if decoded_val and urlparse(decoded_val).scheme in ['http', 'https']:
                            extracted_urls.append(decoded_val)
            except Exception as e:
                continue

    except pefile.PEFormatError as e:
        print(f"PE 파일 포맷 오류: {e}")
        return {"error": f"PE 파일 포맷 오류: {e}"}
    except Exception as e:
        print(f"PE 파일 분석 중 예상치 못한 오류: {e}")
        return {"error": f"PE 파일 분석 중 오류: {e}"}

    return {
        "pe_header_info": pe_header_info,
        "extracted_strings": list(set(extracted_strings)),
        "extracted_urls": list(set(extracted_urls))
    }

# SH 파일 분석 함수 (이전과 동일)
URL_PATTERN = re.compile(r'https?://[^\s\'\"\\|`]+')

def extract_urls_from_text(text):
    return URL_PATTERN.findall(text)

def decode_command_substitution(val, variables):
    inner = val.strip()
    if inner.startswith('$(') and inner.endswith(')'):
        inner_cmd = inner[2:-1].strip()
        parts = inner_cmd.split('|')
        if len(parts) >= 2:
            left = parts[0].strip()
            right = parts[1].strip()

            if left.startswith('echo '):
                echo_content = left[5:].strip().strip('"').strip("'")
                for var, valv in variables.items():
                    echo_content = echo_content.replace(f"${{{var}}}", valv).replace(f"${var}", valv)
                
                if 'base64' in right:
                    decoded_val = decode_base64_string(echo_content)
                    return decoded_val
    return None

def analyze_sh_script(script_content: str):
    variables = {}
    urls_found = set()

    for url in extract_urls_from_text(script_content):
        urls_found.add(url)

    try:
        parts = bashlex.parse(script_content)
    except Exception as e:
        for line in script_content.split('\n'):
            line = line.strip()
            if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*=".*"$', line) or re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*=\$\(.+\)$', line):
                try:
                    key, val_part = line.split('=', 1)
                    key = key.strip()
                    val = val_part.strip().strip('"').strip("'")
                    variables[key] = val

                    b64_block = find_base64_block(val)
                    if b64_block:
                        decoded = decode_base64_string(b64_block)
                        if decoded:
                            for url in extract_urls_from_text(decoded):
                                urls_found.add(url)
                    
                    if val.startswith('$(') and val.endswith(')'):
                        decoded_cmd_sub = decode_command_substitution(val, variables)
                        if decoded_cmd_sub:
                            variables[key] = decoded_cmd_sub
                            for url in extract_urls_from_text(decoded_cmd_sub):
                                urls_found.add(url)
                except ValueError:
                    pass
        return list(urls_found)

    def recursive_walk(node):
        nonlocal variables, urls_found

        if node.kind == 'assignment' and len(node.parts) >= 2:
            key = node.parts[0].word
            val_node = node.parts[1]
            val = ''
            if val_node.kind == 'word':
                val = val_node.word.strip('"').strip("'")
                variables[key] = val
            
                b64_block = find_base64_block(val)
                if b64_block and ('$' not in val) and ('${' not in val):
                    decoded = decode_base64_string(b64_block)
                    if decoded:
                        variables[key] = decoded
                        for url in extract_urls_from_text(decoded):
                            urls_found.add(url)

            elif val_node.kind in ['word', 'command_substitution']:
                val = val_node.word if hasattr(val_node, 'word') else ''
                decoded = decode_command_substitution(val, variables)
                if decoded:
                    variables[key] = decoded
                    for url in extract_urls_from_text(decoded):
                        urls_found.add(url)

        elif node.kind == 'command' and node.parts:
            first_part_word = node.parts[0].word if hasattr(node.parts[0], 'word') else ''
            if '=' in first_part_word and not first_part_word.startswith('$'):
                try:
                    key, val_part = first_part_word.split('=', 1)
                    val = val_part.strip('"').strip("'")
                    variables[key] = val
                    b64_block = find_base64_block(val)
                    if b64_block and ('$' not in val) and ('${' not in val):
                        decoded = decode_base64_string(b64_block)
                        if decoded:
                            variables[key] = decoded
                            for url in extract_urls_from_text(decoded):
                                urls_found.add(url)
                    return
                except ValueError:
                    pass

            args = []
            for p in node.parts[1:]:
                if hasattr(p, 'word'):
                    args.append(p.word)

            resolved_args = []
            for arg in args:
                for var, valv in variables.items():
                    arg = arg.replace(f"${{{var}}}", valv).replace(f"${var}", valv)
                resolved_args.append(arg)
            
            for arg in resolved_args:
                if ('$' not in arg) and ('${' not in arg):
                    b64_block = find_base64_block(arg)
                    if b64_block:
                        decoded = decode_base64_string(b64_block)
                        if decoded:
                            for url in extract_urls_from_text(decoded):
                                urls_found.add(url)
                for url in extract_urls_from_text(arg):
                    urls_found.add(url)

        if hasattr(node, 'parts'):
            for part in node.parts:
                recursive_walk(part)
        if hasattr(node, 'commands'):
            for command in node.commands:
                recursive_walk(command)
        if hasattr(node, 'body'):
            for part in node.body:
                recursive_walk(part)

    for part in parts:
        recursive_walk(part)

    return list(urls_found)

# 파일 업로드 예측 API 엔드포인트 (이전과 동일)
@app.post("/predict_file")
async def predict_file_api(file: UploadFile = File(...)):
    if model is None or tokenizer is None:
        raise HTTPException(status_code=500, detail="모델 또는 토크나이저가 제대로 로드되지 않았습니다.")

    file_extension = os.path.splitext(file.filename)[1].lower()
    file_content_bytes = await file.read()
    
    analysis_results = {}
    extracted_urls_to_classify = []
    file_type = "unknown"

    if file_extension in ['.exe', '.dll', '.sys', '.ocx', '.scr', '.cpl', '.drv']:
        file_type = "pe"
    elif file_extension == '.sh':
        file_type = "sh"
    else:
        if file.content_type == "application/x-msdownload" or file.content_type == "application/octet-stream":
             if file_content_bytes[:2] == b'MZ':
                 file_type = "pe"
        elif file.content_type == "application/x-sh" or file.content_type == "text/plain":
            if file_content_bytes.startswith(b'#!') and b'sh' in file_content_bytes[:10]:
                file_type = "sh"
            
    if file_type == "pe":
        analysis_results = analyze_pe_file(file_content_bytes)
        if "error" in analysis_results:
            raise HTTPException(status_code=400, detail=f"PE 파일 분석 오류: {analysis_results['error']}")
        extracted_urls_to_classify = analysis_results.get("extracted_urls", [])
        
    elif file_type == "sh":
        try:
            script_content = file_content_bytes.decode('utf-8', errors='ignore')
            extracted_urls_to_classify = analyze_sh_script(script_content)
            analysis_results = {"extracted_urls": extracted_urls_to_classify, "script_content_preview": script_content[:500]}
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="SH 파일 인코딩 오류. UTF-8로 인코딩된 텍스트 파일을 업로드하세요.")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"SH 파일 분석 중 오류 발생: {str(e)}")
    else:
        raise HTTPException(status_code=400, detail=f"지원하지 않는 파일 형식입니다. PE 파일(.exe, .dll 등) 또는 SH 파일(.sh)만 업로드할 수 있습니다. (확장자: {file_extension}, Content-Type: {file.content_type})")

    classified_urls = []
    if extracted_urls_to_classify:
        for url in extracted_urls_to_classify:
            classification_result = process_single_url(url)
            classified_urls.append(classification_result)
    
    final_response = {
        "success": True,
        "file_type": file_type,
        "filename": file.filename,
        "analysis_summary": analysis_results,
        "classified_urls": classified_urls
    }
    return final_response

# API 서버의 루트 경로 확인 (이전과 동일)
@app.get("/")
async def read_root():
    return {"message": "URL Classification API is running!"}