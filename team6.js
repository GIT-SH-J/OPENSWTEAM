async function analyzeURL() {
  const url = document.getElementById("urlInput").value;
  const resultArea = document.getElementById("resultArea");
  if (!url) {
    resultArea.innerHTML = "⚠️ URL을 입력하세요.";
    return;
  }
  resultArea.innerHTML = "⏳ 분석 중...";
  try {
    const response = await fetch("http://127.0.0.1:8000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const data = await response.json();
    if (data.success) {
      resultArea.innerHTML = `${data.label_str} (신뢰도: ${data.confidence.toFixed(2)})`;
    } else {
      resultArea.innerHTML = `⚠️ ${data.message}`;
    }
  } catch (error) {
    resultArea.innerHTML = "❌ 분석 실패. 서버 상태를 확인하세요.";
  }
}

try {
  const response = await fetch("http://127.0.0.1:8000/predict", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url })
  });
  console.log("Response:", await response.json());
  const data = await response.json();
  // ... 기존 코드 ...
} catch (error) {
  console.error("Fetch error:", error);
  resultArea.innerHTML = "❌ 분석 실패. 서버 상태를 확인하세요.";
}