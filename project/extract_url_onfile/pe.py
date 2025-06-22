import pefile
import base64
import re   
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from urllib.parse import urlparse, unquote
from decoder.base64_decoder import find_base64_block, decode_base64_string

def analyze_pe_header(file_path):
    """
    PE(Portable Executable) 파일의 주요 헤더 정보를 분석하고 반환합니다.
    :param file_path: PE 파일 경로
    :return: 헤더 정보 딕셔너리
    """
    try:
        pe = pefile.PE(file_path)
        info = {
            "Machine": hex(pe.FILE_HEADER.Machine),
            "NumberOfSections": pe.FILE_HEADER.NumberOfSections,
            "TimeDateStamp": pe.FILE_HEADER.TimeDateStamp,
            "Characteristics": hex(pe.FILE_HEADER.Characteristics),
            "Subsystem": hex(pe.OPTIONAL_HEADER.Subsystem),
            "DllCharacteristics": hex(pe.OPTIONAL_HEADER.DllCharacteristics),
            "ImageBase": hex(pe.OPTIONAL_HEADER.ImageBase),
            "EntryPoint": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        }
        return info
    except Exception as e:
        print(f"[❌] PE 분석 실패: {e}")
        return {}


def extract_strings_from_pe(file_path):
    pe = pefile.PE(file_path)
    strings = []
    for section in pe.sections:
        try:
            data = section.get_data()
            ascii_strings = re.findall(rb'[ -~]{5,}', data)
            strings.extend([s.decode(errors='ignore') for s in ascii_strings])
        except Exception:
            continue
    return strings

def decode_obfuscated_urls_from_pe(file_path):
    strings = extract_strings_from_pe(file_path)
    decoded_urls = []
    for s in strings:
        b64_str = find_base64_block(s)
        if b64_str:
            decoded = decode_base64_string(b64_str)
            if decoded and urlparse(decoded).scheme in ['http', 'https']:
                decoded_urls.append(decoded)
    return decoded_urls


if __name__ == "__main__":
    pe_path = "sample.exe"
    header_info = analyze_pe_header(pe_path)
    print("PE 헤더 정보:", header_info)

    urls = decode_obfuscated_urls_from_pe(pe_path)
    print("디코딩된 URL 리스트:")
    for url in urls:
        print(url)
