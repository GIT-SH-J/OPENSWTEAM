import torch
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
from urllib.parse import urlparse


label_map = {"위험": 0, "주의": 1, "안전": 2}
id2label = {v: k for k, v in label_map.items()}

# 모델과 토크나이저 불러오기
model = DistilBertForSequenceClassification.from_pretrained("saved_model").to("cpu")
tokenizer = DistilBertTokenizerFast.from_pretrained("saved_model")
model.eval()

def preprocess_url(url: str) -> str:
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    return f"{domain} {path}".strip()  # 쿼리 제거

def is_valid_url(url: str) -> bool:
    parsed = urlparse(url)
    return bool(parsed.netloc and '.' in parsed.netloc)

def predict_url(url: str):
    if not url.strip():
        print("❗ 입력값이 비어 있습니다.")
        return None, None, None

    if not is_valid_url(url):
        print("❗ 유효하지 않은 URL 형식입니다. 예: https://example.com")
        return None, None, None


    try:
        processed_url = preprocess_url(url)
        inputs = tokenizer(processed_url, return_tensors="pt", truncation=True, padding="max_length", max_length=128)
        with torch.no_grad():
            outputs = model(**inputs)
            probs = torch.softmax(outputs.logits, dim=1).squeeze()
            label = torch.argmax(probs).item()
            confidence = probs[label].item()

            # confidence가 너무 낮으면 불확실 표시
            if confidence < 0.5:
                label_str = "⚠️ 불확실"
            else:
                label_str = {0: "🔴 위험", 1: "🟡 주의", 2: "🟢 안전"}.get(label, "알 수 없음")

            print(f"\n🌐 {url}")
            print(f"→ {label_str} (신뢰도: {confidence:.2f})")
            return label, confidence, label_str

    except Exception as e:
        print("예측 중 오류 발생:", e)
        return None, None, None

# 테스트 실행
while True:
    user_input = input("\nURL 입력 (종료하려면 'exit'): ").strip()
    if user_input.lower() == "exit":
        break
    predict_url(user_input)
