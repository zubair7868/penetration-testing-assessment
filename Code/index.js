// Enhanced file upload functionality
document.addEventListener('DOMContentLoaded', function() {
    const uploadArea = document.getElementById('uploadArea');
    const fileInput = document.getElementById('fileInput');
    
    // Click to upload
    uploadArea.addEventListener('click', () => {
        fileInput.click();
    });
    
    // Drag and drop functionality
    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.style.background = 'rgba(52, 152, 219, 0.2)';
        uploadArea.style.borderColor = '#2980b9';
    });
    
    uploadArea.addEventListener('dragleave', (e) => {
        e.preventDefault();
        uploadArea.style.background = 'rgba(52, 152, 219, 0.05)';
        uploadArea.style.borderColor = '#3498db';
    });
    
    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.style.background = 'rgba(52, 152, 219, 0.05)';
        uploadArea.style.borderColor = '#3498db';
        
        const files = e.dataTransfer.files;
        if (files.length > 0 && files[0].type === 'application/pdf') {
            handleFileUpload(files[0]);
        } else {
            showAlert('Please upload a PDF file only!', 'error');
        }
    });
    
    // File input change
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileUpload(e.target.files[0]);
        }
    });
});

function handleFileUpload(file) {
    const uploadContent = document.querySelector('.upload-content');
    const fileSize = (file.size / 1024 / 1024).toFixed(2);
    
    uploadContent.innerHTML = `
        <div class="upload-icon">✅</div>
        <p><strong>${file.name}</strong> ready to upload</p>
        <small>File size: ${fileSize} MB</small>
        <div style="margin-top: 15px;">
            <div style="background: #e8f5e8; color: #2e7d32; padding: 10px; border-radius: 8px; font-size: 0.9rem;">
                📄 PDF file detected and validated
            </div>
        </div>
    `;
}

function uploadReport() {
    const title = document.getElementById('reportTitle').value;
    const date = document.getElementById('reportDate').value;
    const network = document.getElementById('targetNetwork').value;
    const fileInput = document.getElementById('fileInput');
    
    if (!title || !date || !network || !fileInput.files.length) {
        showAlert('Please fill all fields and select a PDF file', 'error');
        return;
    }
    
    // Simulate upload progress
    showUploadProgress();
    
    setTimeout(() => {
        addReportToList(title, date, network, fileInput.files[0].name);
        resetUploadForm();
        showAlert('Report uploaded successfully! 🎉', 'success');
    }, 2000);
}

function showUploadProgress() {
    const uploadContent = document.querySelector('.upload-content');
    uploadContent.innerHTML = `
        <div class="upload-icon">⏳</div>
        <p><strong>Uploading...</strong></p>
        <div style="margin-top: 15px;">
            <div style="background: #3498db; height: 4px; border-radius: 2px; animation: loading 2s ease-in-out;">
            </div>
        </div>
    `;
}

function addReportToList(title, date, network, filename) {
    const reportsList = document.getElementById('reportsList');
    const reportItem = document.createElement('div');
    reportItem.className = 'report-item';
    reportItem.style.animation = 'slideIn 0.5s ease-out';
    
    reportItem.innerHTML = `
        <div class="report-info">
            <h3>🎯 ${title}</h3>
            <p><strong>Date:</strong> ${new Date(date).toLocaleDateString()}</p>
            <p><strong>Target:</strong> ${network}</p>
            <p><strong>Status:</strong> <span class="status-complete">Completed</span></p>
            <p><strong>File:</strong> ${filename}</p>
        </div>
        <div class="report-actions">
            <button class="btn-view" onclick="viewReport('${filename}')">📖 View PDF</button>
            <button class="btn-details" onclick="showReportDetails('${title}')">🔍 Details</button>
        </div>
    `;
    
    reportsList.appendChild(reportItem);
}

function resetUploadForm() {
    document.getElementById('reportTitle').value = '';
    document.getElementById('reportDate').value = '';
    document.getElementById('targetNetwork').value = '';
    document.getElementById('fileInput').value = '';
    
    document.querySelector('.upload-content').innerHTML = `
        <div class="upload-icon">📁</div>
        <p>Click or drag PDF files here</p>
        <small>Supports PDF files up to 10MB</small>
    `;
}

function viewReport(filename) {
    showAlert(`Opening ${filename}...`, 'info');
    // In a real implementation, this would open the uploaded PDF
    setTimeout(() => {
        window.open('#', '_blank');
    }, 1000);
}

function viewMainReport() {
    showAlert('Opening main penetration testing report...', 'info');
    // You can link this to your actual PDF file
    setTimeout(() => {
        showReportDetails('SME Network Penetration Test');
    }, 1000);
}

function showDetails() {
    showReportDetails('SME Network Penetration Test');
}

function showReportDetails(reportTitle) {
    const modal = createModal('Report Details', `
        <div style="text-align: left;">
            <h3 style="color: #1a1a2e; margin-bottom: 20px;">📊 ${reportTitle}</h3>
            
            <div style="margin-bottom: 20px;">
                <h4 style="color: #e74c3c; margin-bottom: 10px;">🎯 Target Systems:</h4>
                <ul style="margin-left: 20px;">
                    <li><strong>Desktop:</strong> 192.168.10.20 (Windows 7) - ✅ Compromised</li>
                    <li><strong>Server:</strong> 192.168.10.10 (CentOS) - ✅ Compromised</li>
                </ul>
            </div>
            
            <div style="margin-bottom: 20px;">
                <h4 style="color: #e74c3c; margin-bottom: 10px;">🔓 Exploits Used:</h4>
                <ul style="margin-left: 20px;">
                    <li><strong>MS17-010 EternalBlue</strong> - Remote code execution</li>
                    <li><strong>Password Cracking</strong> - Hydra + John the Ripper</li>
                    <li><strong>Web Authentication Bypass</strong> - Manual exploitation</li>
                </ul>
            </div>
            
            <div style="margin-bottom: 20px;">
                <h4 style="color: #e74c3c; margin-bottom: 10px;">💰 Compromised Credentials:</h4>
                <ul style="margin-left: 20px;">
                    <li>lbrown : lovely</li>
                    <li>mbrown : Liverpool</li>
                    <li>root : superman</li>
                </ul>
            </div>
            
            <div>
                <h4 style="color: #27ae60; margin-bottom: 10px;">🛡️ Recommendations:</h4>
                <ul style="margin-left: 20px;">
                    <li>Apply MS17-010 security patches immediately</li>
                    <li>Implement strong password policies</li>
                    <li>Enable HTTPS for web applications</li>
                    <li>Regular vulnerability assessments</li>
                </ul>
            </div>
        </div>
    `);
    
    document.body.appendChild(modal);
}

function createModal(title, content) {
    const modal = document.createElement('div');
    modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.8);
        display: flex;
        justify-content: center;
        align-items: center;
        z-index: 1000;
        animation: fadeIn 0.3s ease-out;
    `;
    
    modal.innerHTML = `
        <div style="
            background: white;
            padding: 30px;
            border-radius: 15px;
            max-width: 600px;
            max-height: 80vh;
            overflow-y: auto;
            position: relative;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.3);
        ">
            <button onclick="this.closest('div').parentElement.remove()" style="
                position: absolute;
                top: 15px;
                right: 15px;
                background: #e74c3c;
                color: white;
                border: none;
                border-radius: 50%;
                width: 30px;
                height: 30px;
                cursor: pointer;
                font-size: 16px;
            ">×</button>
            <h2 style="color: #1a1a2e; margin-bottom: 20px;">${title}</h2>
            ${content}
        </div>
    `;
    
    return modal;
}

function showAlert(message, type = 'info') {
    const alertDiv = document.createElement('div');
    const colors = {
        success: '#27ae60',
        error: '#e74c3c',
        info: '#3498db'
    };
    
    alertDiv.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${colors[type]};
        color: white;
        padding: 15px 25px;
        border-radius: 10px;
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
        z-index: 1001;
        animation: slideInRight 0.5s ease-out;
        font-weight: 600;
    `;
    
    alertDiv.textContent = message;
    document.body.appendChild(alertDiv);
    
    setTimeout(() => {
        alertDiv.style.animation = 'slideOutRight 0.5s ease-in';
        setTimeout(() => alertDiv.remove(), 500);
    }, 3000);
}

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
    }
    
    @keyframes slideIn {
        from { transform: translateX(-100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    @keyframes slideInRight {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    @keyframes slideOutRight {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
    
    @keyframes loading {
        0% { width: 0%; }
        100% { width: 100%; }
    }
`;
document.head.appendChild(style);

// Initialize
console.log('🛡️ Penetration Testing Dashboard Loaded Successfully!');
