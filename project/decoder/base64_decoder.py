import base64
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote



BASE64_BLOCK_PATTERN = re.compile(r'[A-Za-z0-9+/]{10,}(?:={0,2})?') # 최소 10자, 선택적 패딩

def find_base64_block(text: str) -> str | None:
    # 강화된 Base64 패턴 사용
    matches = BASE64_BLOCK_PATTERN.findall(text)
    if matches:
        # 가장 긴 매치보다는, 첫 번째 유효한 매치를 우선
        # 여기서는 단순히 첫 번째 매치를 반환합니다.
        # 실제로는 유효한 base64인지 디코딩까지 시도해보는 것이 더 견고합니다.
        return matches[0]
    return None

def decode_base64_string(b64_string: str) -> str | None:
    try:
        b64_string = b64_string.strip().strip('"').strip("'")
        b64_string = b64_string.replace('-', '+').replace('_', '/')

        missing_padding = len(b64_string) % 4
        if missing_padding:
            b64_string += '=' * (4 - missing_padding)

        decoded_bytes = base64.b64decode(b64_string, validate=False)
        decoded_str = decoded_bytes.decode('utf-8', errors='ignore').strip()

        # 디버깅 추가: 왜 None이 반환되는지 확인
        if not (decoded_str.startswith("http://") or decoded_str.startswith("https://")):
            
            return None
        if len(decoded_str) < 5:
       
            return None

        return decoded_str
    except Exception as e:
        return None

# 이 함수는 현재 스크립트에서 직접 사용되지 않지만, 기존 base64_decoder.py에 있었으므로 포함합니다.
def decode_obfuscated_url_preserve_query(url: str) -> str:
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query, keep_blank_values=True)

    for key, values in query_params.items():
        new_values = []
        for val in values:
            b64_str = find_base64_block(val)
            if b64_str:
                decoded = decode_base64_string(b64_str)
                if decoded:
                    new_values.append(decoded)
                    continue
            new_values.append(val)
        query_params[key] = new_values

    new_query = urlencode(query_params, doseq=True)

    new_url = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))
    return new_url
# 테스트

