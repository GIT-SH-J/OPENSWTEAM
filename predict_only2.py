import torch
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
from urllib.parse import urlparse, urlunparse

# === [0] 장치 설정 ===
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print("📟 실행 장치:", device)

# === [1] 모델과 토크나이저 불러오기 ===
model = DistilBertForSequenceClassification.from_pretrained("saved_model").to(device)
tokenizer = DistilBertTokenizerFast.from_pretrained("saved_model")

# === [2] URL 정규화 함수 ===
def normalize_url(url):
    parsed = urlparse(url.strip())
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))

# === [3] 예측 함수 ===
def predict_url(url: str):
    # 1) 정규화
    norm_url = normalize_url(url)
    
    # 2) 입력 텐서화
    model.eval()
    inputs = tokenizer(norm_url, return_tensors="pt", truncation=True, padding="max_length", max_length=128)
    inputs = {k: v.to(device) for k, v in inputs.items()}
    
    # 3) 예측
    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=1).squeeze()
        label = torch.argmax(probs).item()
        confidence = probs[label].item()
        
        # 4) 확신 낮은 위험은 주의로 완화
        if label == 0 and confidence < 0.85:
            label = 1
        
        label_str = {0: "🔴 위험", 1: "🟡 주의", 2: "🟢 안전"}[label]
        print(f"\n🌐 원본 URL: {url}")
        print(f"🔧 정규화된 URL: {norm_url}")
        print(f"→ 예측 결과: {label_str} (신뢰도: {confidence:.2f})")

# === [4] 사용자 입력 루프 ===
while True:
    user_input = input("\nURL 입력 (종료하려면 'exit'): ")
    if user_input.lower() == "exit":
        break
    predict_url(user_input)
