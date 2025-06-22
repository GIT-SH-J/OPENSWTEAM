// 단일 URL 분석 관련 요소
const singleUrlResultContainer = document.getElementById("singleUrlResultContainer");
const originalUrlDisplay = document.getElementById("originalUrlDisplay");
const decodedUrlDisplay = document.getElementById("decodedUrlDisplay");
const predictionResult = document.getElementById("predictionResult");

// 파일 업로드 분석 관련 요소
const fileInput = document.getElementById("fileInput");
const fileResultContainer = document.getElementById("fileResultContainer");
const fileResultTitle = document.getElementById("fileResultTitle");
const fileResultsList = document.getElementById("fileResultsList");


// 결과 영역 초기화 함수
function clearResults() {
    // 단일 URL 결과 초기화
    originalUrlDisplay.textContent = "";
    decodedUrlDisplay.textContent = "";
    predictionResult.textContent = "";
    predictionResult.className = "prediction-result";
    singleUrlResultContainer.style.display = "none";

    // 파일 업로드 결과 초기화
    fileResultTitle.textContent = "";
    fileResultsList.innerHTML = ""; // 기존 리스트 항목 제거
    fileResultContainer.style.display = "none";
}

// === 단일 URL 분석 함수 ===
async function analyzeURL() {
    clearResults(); // 모든 결과 영역 초기화

    const url = document.getElementById("urlInput").value;
    if (!url) {
        predictionResult.textContent = "⚠️ URL을 입력하세요.";
        predictionResult.className += " yellow";
        singleUrlResultContainer.style.display = "inline-block";
        return;
    }

    predictionResult.textContent = "⏳ 분석 중...";
    predictionResult.className += " info"; // 정보 색상으로 변경
    singleUrlResultContainer.style.display = "inline-block";

    try {
        const response = await fetch("http://127.0.0.1:8000/predict", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`HTTP error! status: ${response.status}, message: ${errorText}`);
        }

        const data = await response.json();
        console.log("Response data (single URL):", data);

        singleUrlResultContainer.style.display = "inline-block";

        if (data.success) {
            originalUrlDisplay.textContent = data.original_url || "N/A";
            decodedUrlDisplay.textContent = data.decoded_url || "N/A";

            let resultClass = "";
            if (data.label_str.includes("안전")) {
                resultClass = "green";
            } else if (data.label_str.includes("주의")) {
                resultClass = "yellow";
            } else if (data.label_str.includes("위험")) {
                resultClass = "red";
            }

            predictionResult.textContent = `→ 예측 결과: ${data.label_str} (신뢰도: ${data.confidence.toFixed(2)})`;
            predictionResult.className = `prediction-result ${resultClass}`;

        } else {
            originalUrlDisplay.textContent = url;
            decodedUrlDisplay.textContent = "디코딩 실패 또는 해당 없음";
            predictionResult.textContent = `⚠️ 분석 실패: ${data.message || '알 수 없는 오류'}`;
            predictionResult.className = "prediction-result red";
        }
    } catch (error) {
        console.error("Fetch error (single URL):", error);
        originalUrlDisplay.textContent = url;
        decodedUrlDisplay.textContent = "통신 오류로 디코딩 불가";
        predictionResult.textContent = `❌ 분석 실패. 서버 상태를 확인하세요. 오류: ${error.message}`;
        predictionResult.className = "prediction-result red";
        singleUrlResultContainer.style.display = "inline-block";
    }
}

// === 파일 업로드 분석 함수 ===
async function uploadFile() {
    clearResults(); // 모든 결과 영역 초기화

    const file = fileInput.files[0];
    if (!file) {
        fileResultTitle.textContent = "⚠️ 파일을 선택하세요.";
        fileResultTitle.className = "prediction-result yellow";
        fileResultContainer.style.display = "inline-block";
        return;
    }

    fileResultTitle.textContent = `⏳ 파일 '${file.name}' 분석 중...`;
    fileResultTitle.className = "prediction-result info";
    fileResultContainer.style.display = "inline-block";
    fileResultsList.innerHTML = ""; // 이전 목록 초기화

    const formData = new FormData();
    formData.append("file", file);

    try {
        const response = await fetch("http://127.0.0.1:8000/predict_file", {
            method: "POST",
            body: formData,
        });

        if (!response.ok) {
            const errorData = await response.json(); // FastAPI HTTPException은 JSON으로 응답
            throw new Error(`HTTP error! status: ${response.status}, detail: ${errorData.detail}`);
        }

        const data = await response.json();
        console.log("Response data (file upload):", data);

        fileResultContainer.style.display = "inline-block";

        if (data.success) {
            fileResultTitle.textContent = `✅ 파일 '${data.filename}' (${data.file_type.toUpperCase()}) 분석 완료`;
            fileResultTitle.className = "prediction-result green";

            // PE 파일 헤더 정보 표시
            if (data.file_type === "pe" && data.analysis_summary && Object.keys(data.analysis_summary.pe_header_info).length > 0) {
                const headerInfoItem = document.createElement("li");
                headerInfoItem.className = "file-result-item info";
                let headerHtml = "<b>PE 헤더 정보:</b><br>";
                for (const key in data.analysis_summary.pe_header_info) {
                    headerHtml += `${key}: ${data.analysis_summary.pe_header_info[key]}<br>`;
                }
                // ⭐⭐⭐ 이 부분을 수정했습니다. ⭐⭐⭐
                headerInfoItem.innerHTML = headerHtml;
                fileResultsList.appendChild(headerInfoItem);
            }
            // SH 파일 미리보기 (옵션)
            if (data.file_type === "sh" && data.analysis_summary && data.analysis_summary.script_content_preview) {
                const previewItem = document.createElement("li");
                previewItem.className = "file-result-item info";
                previewItem.innerHTML = `<b>스크립트 미리보기 (첫 500자):</b><pre>${data.analysis_summary.script_content_preview}</pre>`;
                fileResultsList.appendChild(previewItem);
            }

            // 추출된 URL 분류 결과 표시
            if (data.classified_urls && data.classified_urls.length > 0) {
                const urlCountItem = document.createElement("li");
                urlCountItem.className = "file-result-item";
                urlCountItem.innerHTML = `<b>총 ${data.classified_urls.length}개의 URL이 추출 및 분석되었습니다.</b>`;
                fileResultsList.appendChild(urlCountItem);

                data.classified_urls.forEach(item => {
                    const listItem = document.createElement("li");
                    listItem.className = "file-result-item";

                    let resultClass = "";
                    if (item.label_str.includes("안전")) {
                        resultClass = "green";
                    } else if (item.label_str.includes("주의")) {
                        resultClass = "yellow";
                    } else if (item.label_str.includes("위험")) {
                        resultClass = "red";
                    }

                    listItem.innerHTML = `
                        <span class="${resultClass}">
                            <span class="result-label">원본 URL:</span> ${item.original_url || 'N/A'}<br>
                            <span class="result-label">디코드 URL:</span> ${item.decoded_url || 'N/A'}<br>
                            <span class="result-label">결과:</span> ${item.label_str} (신뢰도: ${item.confidence.toFixed(2)})
                        </span>
                    `;
                    fileResultsList.appendChild(listItem);
                });
            } else {
                const noUrlItem = document.createElement("li");
                noUrlItem.className = "file-result-item yellow";
                noUrlItem.textContent = "파일에서 분석할 URL을 찾을 수 없습니다.";
                fileResultsList.appendChild(noUrlItem);
            }
        } else {
            fileResultTitle.textContent = `❌ 파일 분석 실패: ${data.message || '알 수 없는 오류'}`;
            fileResultTitle.className = "prediction-result red";
            fileResultsList.innerHTML = `<li>오류 발생: ${data.message || '서버 응답 오류'}</li>`;
        }
    } catch (error) {
        console.error("Fetch error (file upload):", error);
        fileResultTitle.textContent = `❌ 파일 분석 실패. 서버 상태를 확인하세요. 오류: ${error.message}`;
        fileResultTitle.className = "prediction-result red";
        fileResultContainer.style.display = "inline-block";
        fileResultsList.innerHTML = `<li>통신 오류: ${error.message}</li>`;
    }
}