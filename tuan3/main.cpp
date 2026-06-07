#include <wx/wx.h>
#include <wx/filedlg.h>
#include <wx/textfile.h>
#include <wx/clipbrd.h>
#include <ctime>
#include <cstdlib>
#include <vector>
#include <string>

#include "des_crypto.h"

class DESAppFrame : public wxFrame
{
private:
    // Cột Mã Hóa
    wxTextCtrl* txtPlain;
    wxTextCtrl* txtEncryptKey;
    wxChoice* choiceEncFormat;
    wxTextCtrl* txtCipherOutput;

    // Cột Giải Mã
    wxTextCtrl* txtCipherInput;
    wxTextCtrl* txtDecryptKey;
    wxChoice* choiceDecFormat;
    wxTextCtrl* txtPlainOutput;

public:
    DESAppFrame()
    : wxFrame(
        NULL,
        wxID_ANY,
        wxString::FromUTF8("Chương trình Mã hóa & Giải mã DES nâng cao"),
        wxDefaultPosition,
        wxSize(1150, 750))
    {
        CreateStatusBar(2);
        SetStatusText(wxString::FromUTF8("Trạng thái: Sẵn sàng"), 0);
        SetStatusText("Môi trường: UCRT64 + OpenSSL", 1);

        wxPanel* panel = new wxPanel(this);
        wxBoxSizer* mainSizer = new wxBoxSizer(wxHORIZONTAL);

        wxArrayString formats;
        formats.Add("Base64");
        formats.Add("Hex");

        // =======================================================
        // KHỐI MÃ HÓA (BÊN TRÁI)
        // =======================================================
        wxStaticBoxSizer* encBox = new wxStaticBoxSizer(wxVERTICAL, panel, wxString::FromUTF8("🔒 MÃ HÓA"));

        // Tiêu đề văn bản gốc + Nút Tải tệp
        wxBoxSizer* plainLabelSizer = new wxBoxSizer(wxHORIZONTAL);
        plainLabelSizer->Add(new wxStaticText(panel, wxID_ANY, wxString::FromUTF8("Văn bản gốc:")), 1, wxALIGN_CENTER_VERTICAL);
        wxButton* btnLoadPlain = new wxButton(panel, wxID_ANY, wxString::FromUTF8("📂 Tải tệp"), wxDefaultPosition, wxSize(95, 25));
        plainLabelSizer->Add(btnLoadPlain, 0);
        encBox->Add(plainLabelSizer, 0, wxEXPAND | wxALL, 5);

        txtPlain = new wxTextCtrl(panel, wxID_ANY, "", wxDefaultPosition, wxSize(-1, 120), wxTE_MULTILINE);
        encBox->Add(txtPlain, 0, wxEXPAND | wxALL, 5);

        encBox->Add(new wxStaticText(panel, wxID_ANY, wxString::FromUTF8("🔑 Khóa (8 ký tự):")), 0, wxALL, 5);
        txtEncryptKey = new wxTextCtrl(panel, wxID_ANY, "");
        encBox->Add(txtEncryptKey, 0, wxEXPAND | wxALL, 5);

        // Hàng nút Sinh khóa + Lưu khóa
        wxBoxSizer* encKeyBtnSizer = new wxBoxSizer(wxHORIZONTAL);
        encKeyBtnSizer->AddStretchSpacer(1);
        wxButton* btnGenKey = new wxButton(panel, wxID_ANY, wxString::FromUTF8("🔄 Sinh khóa"), wxDefaultPosition, wxSize(105, 28));
        wxButton* btnSaveEncKey = new wxButton(panel, wxID_ANY, wxString::FromUTF8("💾 Lưu khóa"), wxDefaultPosition, wxSize(105, 28));
        encKeyBtnSizer->Add(btnGenKey, 0, wxRIGHT, 5);
        encKeyBtnSizer->Add(btnSaveEncKey, 0);
        encBox->Add(encKeyBtnSizer, 0, wxEXPAND | wxALL, 5);

        // Định dạng lựa chọn đầu ra
        wxBoxSizer* formatEncSizer = new wxBoxSizer(wxHORIZONTAL);
        formatEncSizer->Add(new wxStaticText(panel, wxID_ANY, wxString::FromUTF8("Định dạng đầu ra:")), 1, wxALIGN_CENTER_VERTICAL);
        choiceEncFormat = new wxChoice(panel, wxID_ANY, wxDefaultPosition, wxDefaultSize, formats);
        choiceEncFormat->SetSelection(0);
        formatEncSizer->Add(choiceEncFormat, 1, wxEXPAND);
        encBox->Add(formatEncSizer, 0, wxEXPAND | wxALL, 5);

        // Tiêu đề Kết quả + Nút Lưu tệp
        wxBoxSizer* cipherTitleSizer = new wxBoxSizer(wxHORIZONTAL);
        cipherTitleSizer->Add(new wxStaticText(panel, wxID_ANY, wxString::FromUTF8("Văn bản Mã Hóa:")), 1, wxALIGN_CENTER_VERTICAL);
        wxButton* btnSaveCipher = new wxButton(panel, wxID_ANY, wxString::FromUTF8("💾 Lưu tệp"), wxDefaultPosition, wxSize(95, 25));
        cipherTitleSizer->Add(btnSaveCipher, 0);
        encBox->Add(cipherTitleSizer, 0, wxEXPAND | wxALL, 5);

        txtCipherOutput = new wxTextCtrl(panel, wxID_ANY, "", wxDefaultPosition, wxSize(-1, 120), wxTE_MULTILINE | wxTE_READONLY);
        encBox->Add(txtCipherOutput, 0, wxEXPAND | wxALL, 5);

        // Hàng nút hành động Khối Mã hóa
        wxBoxSizer* encActionSizer = new wxBoxSizer(wxHORIZONTAL);
        wxButton* btnEncrypt = new wxButton(panel, wxID_ANY, wxString::FromUTF8("🟢 Mã Hóa"));
        wxButton* btnClearEnc = new wxButton(panel, wxID_ANY, wxString::FromUTF8("❌ Xóa dữ liệu"));
        wxButton* btnCopyEnc = new wxButton(panel, wxID_ANY, wxString::FromUTF8("📋 Copy"));
        wxButton* btnSaveEncResult = new wxButton(panel, wxID_ANY, wxString::FromUTF8("💾 Lưu kết quả"));
        encActionSizer->Add(btnEncrypt, 1, wxRIGHT, 3);
        encActionSizer->Add(btnClearEnc, 1, wxRIGHT, 3);
        encActionSizer->Add(btnCopyEnc, 1, wxRIGHT, 3);
        encActionSizer->Add(btnSaveEncResult, 1);
        encBox->Add(encActionSizer, 0, wxEXPAND | wxTOP, 15);


        // =======================================================
        // KHỐI GIẢI MÃ (BÊN PHẢI)
        // =======================================================
        wxStaticBoxSizer* decBox = new wxStaticBoxSizer(wxVERTICAL, panel, wxString::FromUTF8("🔓 GIẢI MÃ"));

        // Tiêu đề văn bản mã hóa + Nút Tải tệp
        wxBoxSizer* cipherLabelSizer = new wxBoxSizer(wxHORIZONTAL);
        cipherLabelSizer->Add(new wxStaticText(panel, wxID_ANY, wxString::FromUTF8("Văn bản mã hóa:")), 1, wxALIGN_CENTER_VERTICAL);
        wxButton* btnLoadCipher = new wxButton(panel, wxID_ANY, wxString::FromUTF8("📂 Tải tệp"), wxDefaultPosition, wxSize(95, 25));
        cipherLabelSizer->Add(btnLoadCipher, 0);
        decBox->Add(cipherLabelSizer, 0, wxEXPAND | wxALL, 5);

        txtCipherInput = new wxTextCtrl(panel, wxID_ANY, "", wxDefaultPosition, wxSize(-1, 120), wxTE_MULTILINE);
        decBox->Add(txtCipherInput, 0, wxEXPAND | wxALL, 5);

        decBox->Add(new wxStaticText(panel, wxID_ANY, wxString::FromUTF8("🔑 Khóa (8 ký tự):")), 0, wxALL, 5);
        txtDecryptKey = new wxTextCtrl(panel, wxID_ANY, "");
        decBox->Add(txtDecryptKey, 0, wxEXPAND | wxALL, 5);

        // Hàng nút Tải khóa + Lưu khóa
        wxBoxSizer* decKeyBtnSizer = new wxBoxSizer(wxHORIZONTAL);
        decKeyBtnSizer->AddStretchSpacer(1);
        wxButton* btnLoadDecKey = new wxButton(panel, wxID_ANY, wxString::FromUTF8("📂 Tải Khóa"), wxDefaultPosition, wxSize(105, 28));
        wxButton* btnSaveDecKey = new wxButton(panel, wxID_ANY, wxString::FromUTF8("💾 Lưu Khóa"), wxDefaultPosition, wxSize(105, 28));
        decKeyBtnSizer->Add(btnLoadDecKey, 0, wxRIGHT, 5);
        decKeyBtnSizer->Add(btnSaveDecKey, 0);
        decBox->Add(decKeyBtnSizer, 0, wxEXPAND | wxALL, 5);

        // Định dạng lựa chọn đầu vào
        wxBoxSizer* formatDecSizer = new wxBoxSizer(wxHORIZONTAL);
        formatDecSizer->Add(new wxStaticText(panel, wxID_ANY, wxString::FromUTF8("Định dạng đầu vào:")), 1, wxALIGN_CENTER_VERTICAL);
        choiceDecFormat = new wxChoice(panel, wxID_ANY, wxDefaultPosition, wxDefaultSize, formats);
        choiceDecFormat->SetSelection(0);
        formatDecSizer->Add(choiceDecFormat, 1, wxEXPAND);
        decBox->Add(formatDecSizer, 0, wxEXPAND | wxALL, 5);

        // Tiêu đề Văn bản Giải Mã + Nút Lưu tệp
        wxBoxSizer* plainOutTitleSizer = new wxBoxSizer(wxHORIZONTAL);
        plainOutTitleSizer->Add(new wxStaticText(panel, wxID_ANY, wxString::FromUTF8("Văn bản Giải Mã:")), 1, wxALIGN_CENTER_VERTICAL);
        wxButton* btnSavePlain = new wxButton(panel, wxID_ANY, wxString::FromUTF8("💾 Lưu tệp"), wxDefaultPosition, wxSize(95, 25));
        plainOutTitleSizer->Add(btnSavePlain, 0);
        decBox->Add(plainOutTitleSizer, 0, wxEXPAND | wxALL, 5);

        txtPlainOutput = new wxTextCtrl(panel, wxID_ANY, "", wxDefaultPosition, wxSize(-1, 120), wxTE_MULTILINE | wxTE_READONLY);
        decBox->Add(txtPlainOutput, 0, wxEXPAND | wxALL, 5);

        // Hàng nút hành động Khối Giải mã
        wxBoxSizer* decActionSizer = new wxBoxSizer(wxHORIZONTAL);
        wxButton* btnDecrypt = new wxButton(panel, wxID_ANY, wxString::FromUTF8("🟢 Giải mã"));
        wxButton* btnClearDec = new wxButton(panel, wxID_ANY, wxString::FromUTF8("❌ Xóa dữ liệu"));
        wxButton* btnCopyDec = new wxButton(panel, wxID_ANY, wxString::FromUTF8("📋 Copy"));
        wxButton* btnSaveDecResult = new wxButton(panel, wxID_ANY, wxString::FromUTF8("💾 Lưu kết quả"));
        decActionSizer->Add(btnDecrypt, 1, wxRIGHT, 3);
        decActionSizer->Add(btnClearDec, 1, wxRIGHT, 3);
        decActionSizer->Add(btnCopyDec, 1, wxRIGHT, 3);
        decActionSizer->Add(btnSaveDecResult, 1);
        decBox->Add(decActionSizer, 0, wxEXPAND | wxTOP, 15);

        // Đóng gói layout
        mainSizer->Add(encBox, 1, wxEXPAND | wxALL, 10);
        mainSizer->Add(decBox, 1, wxEXPAND | wxALL, 10);
        panel->SetSizer(mainSizer);

        // Đăng ký liên kết sự kiện nút bấm
        btnEncrypt->Bind(wxEVT_BUTTON, &DESAppFrame::OnEncrypt, this);
        btnDecrypt->Bind(wxEVT_BUTTON, &DESAppFrame::OnDecrypt, this);
        btnGenKey->Bind(wxEVT_BUTTON, &DESAppFrame::OnGenerateKey, this);
        btnCopyEnc->Bind(wxEVT_BUTTON, &DESAppFrame::OnCopyEncrypt, this);
        btnCopyDec->Bind(wxEVT_BUTTON, &DESAppFrame::OnCopyDecrypt, this);
        btnClearEnc->Bind(wxEVT_BUTTON, &DESAppFrame::OnClearEncrypt, this);
        btnClearDec->Bind(wxEVT_BUTTON, &DESAppFrame::OnClearDecrypt, this);
        
        btnLoadPlain->Bind(wxEVT_BUTTON, &DESAppFrame::OnLoadPlainFile, this);
        btnLoadCipher->Bind(wxEVT_BUTTON, &DESAppFrame::OnLoadCipherFile, this);
        btnSaveCipher->Bind(wxEVT_BUTTON, &DESAppFrame::OnSaveEncResult, this);
        btnSavePlain->Bind(wxEVT_BUTTON, &DESAppFrame::OnSaveDecResult, this);
        btnSaveEncKey->Bind(wxEVT_BUTTON, &DESAppFrame::OnSaveKey, this);
        btnSaveDecKey->Bind(wxEVT_BUTTON, &DESAppFrame::OnSaveKey, this);
        btnLoadDecKey->Bind(wxEVT_BUTTON, &DESAppFrame::OnLoadKey, this);
        btnSaveEncResult->Bind(wxEVT_BUTTON, &DESAppFrame::OnSaveEncResult, this);
        btnSaveDecResult->Bind(wxEVT_BUTTON, &DESAppFrame::OnSaveDecResult, this);
    }

private:
    void OnGenerateKey(wxCommandEvent&)
    {
        std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        std::string key;
        for(int i=0; i<8; i++) {
            key += chars[rand() % chars.size()];
        }
        txtEncryptKey->SetValue(key);
        txtDecryptKey->SetValue(key);
        
        wxMessageBox(wxString::FromUTF8("Đã tự động sinh khóa ngẫu nhiên 8 ký tự thành công!"), wxString::FromUTF8("Thành công"), wxOK | wxICON_INFORMATION);
        SetStatusText(wxString::FromUTF8("Thông báo: Đã tự động sinh khóa."), 0);
    }

    void OnEncrypt(wxCommandEvent&)
    {
        wxString plainWx = txtPlain->GetValue().Trim(true).Trim(false);
        plainWx.Replace("\r", ""); plainWx.Replace("\n", "");

        if (plainWx.IsEmpty()) {
            wxMessageBox(wxString::FromUTF8("Mã hóa thất bại! Vui lòng nhập văn bản gốc cần mã hóa."), wxString::FromUTF8("Thất bại"), wxOK | wxICON_ERROR);
            return;
        }

        wxCharBuffer buf = plainWx.ToUTF8();
        std::vector<unsigned char> plainBytes(buf.data(), buf.data() + buf.length());
        
        // FIX LỖI: Loại bỏ triệt để khoảng trắng thừa hoặc ký tự rác ẩn bám vào ô Khóa
        wxString keyWx = txtEncryptKey->GetValue().Trim(true).Trim(false);
        keyWx.Replace("\r", ""); keyWx.Replace("\n", ""); keyWx.Replace(" ", "");
        std::string key = std::string(keyWx.utf8_str());

        if (key.length() != 8) {
            wxMessageBox(wxString::FromUTF8("Mã hóa thất bại! Khóa bắt buộc phải có độ dài đúng 8 ký tự."), wxString::FromUTF8("Thất bại"), wxOK | wxICON_ERROR);
            return;
        }

        bool useHex = choiceEncFormat->GetSelection() == 1;
        std::string cipher = DESCrypto::Encrypt(plainBytes, key, useHex);

        txtCipherOutput->SetValue(wxString::FromUTF8(cipher.c_str()));
        wxMessageBox(wxString::FromUTF8("Mã hóa dữ liệu thành công!"), wxString::FromUTF8("Thành công"), wxOK | wxICON_INFORMATION);
        SetStatusText(wxString::FromUTF8("Trạng thái: Mã hóa dữ liệu thành công."), 0);
    }

    void OnDecrypt(wxCommandEvent&)
    {
        wxString cipherWx = txtCipherInput->GetValue().Trim(true).Trim(false);
        cipherWx.Replace("\r", ""); cipherWx.Replace("\n", "");

        if (cipherWx.IsEmpty()) {
            wxMessageBox(wxString::FromUTF8("Giải mã thất bại! Vui lòng dán chuỗi mật mã cần giải mã."), wxString::FromUTF8("Thất bại"), wxOK | wxICON_ERROR);
            return;
        }

        std::string cipher = std::string(cipherWx.utf8_str());
        
        // FIX LỖI: Ép sạch rác nhị phân ngầm và khoảng trắng của ô Khóa Giải mã
        wxString keyWx = txtDecryptKey->GetValue().Trim(true).Trim(false);
        keyWx.Replace("\r", ""); keyWx.Replace("\n", ""); keyWx.Replace(" ", "");
        std::string key = std::string(keyWx.utf8_str());

        if (key.length() != 8) {
            wxMessageBox(wxString::FromUTF8("Giải mã thất bại! Khóa giải mã phải đúng 8 ký tự."), wxString::FromUTF8("Thất bại"), wxOK | wxICON_ERROR);
            return;
        }

        try {
            bool useHex = choiceDecFormat->GetSelection() == 1;
            std::vector<unsigned char> plainBytes = DESCrypto::Decrypt(cipher, key, useHex);
            
            if(plainBytes.empty()) throw std::runtime_error("Lỗi");
            
            wxString plainResult = wxString::FromUTF8(reinterpret_cast<const char*>(plainBytes.data()), plainBytes.size());
            txtPlainOutput->SetValue(plainResult);
            
            wxMessageBox(wxString::FromUTF8("Giải mã dữ liệu thành công!"), wxString::FromUTF8("Thành công"), wxOK | wxICON_INFORMATION);
            SetStatusText(wxString::FromUTF8("Trạng thái: Giải mã thành công."), 0);
        } 
        catch (...) {
            wxMessageBox(wxString::FromUTF8("Giải mã thất bại! Vui lòng kiểm tra lại khóa hoặc định dạng chuỗi mã hóa."), wxString::FromUTF8("Thất bại"), wxOK | wxICON_ERROR);
            SetStatusText(wxString::FromUTF8("Trạng thái: Giải mã thất bại."), 0);
        }
    }

    void HandleLoadFile(wxTextCtrl* target) {
        wxFileDialog openFileDialog(this, wxString::FromUTF8("Chọn tệp văn bản để mở"), "", "", "Text files (*.txt)|*.txt", wxFD_OPEN | wxFD_FILE_MUST_EXIST);
        if (openFileDialog.ShowModal() == wxID_CANCEL) return;
        
        if (target->LoadFile(openFileDialog.GetPath())) {
            wxMessageBox(wxString::FromUTF8("Tải nội dung tệp lên phần mềm thành công!"), wxString::FromUTF8("Thành công"), wxOK | wxICON_INFORMATION);
            SetStatusText(wxString::FromUTF8("Thông báo: Tải tệp thành công."), 0);
        } else {
            wxMessageBox(wxString::FromUTF8("Không thể đọc tệp văn bản này!"), wxString::FromUTF8("Thất bại"), wxOK | wxICON_ERROR);
        }
    }

    void HandleSaveFile(const wxString& content) {
        if(content.IsEmpty()) {
            wxMessageBox(wxString::FromUTF8("Không thể xuất file vì không có dữ liệu!"), wxString::FromUTF8("Thất bại"), wxOK | wxICON_WARNING);
            return;
        }
        wxFileDialog saveFileDialog(this, wxString::FromUTF8("Lưu tệp văn bản"), "", "", "Text files (*.txt)|*.txt", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
        if (saveFileDialog.ShowModal() == wxID_CANCEL) return;
        
        wxTextFile file(saveFileDialog.GetPath());
        if (!file.Exists()) file.Create();
        file.Open(); file.Clear(); file.AddLine(content);
        
        if (file.Write()) {
            wxMessageBox(wxString::FromUTF8("Đã xuất và lưu tệp ra máy tính thành công!"), wxString::FromUTF8("Thành công"), wxOK | wxICON_INFORMATION);
            SetStatusText(wxString::FromUTF8("Thông báo: Xuất tệp thành công."), 0);
        } else {
            wxMessageBox(wxString::FromUTF8("Lưu tệp thất bại! Quyền ghi thư mục bị chặn."), wxString::FromUTF8("Thất bại"), wxOK | wxICON_ERROR);
        }
        file.Close();
    }

    void OnLoadPlainFile(wxCommandEvent&) { HandleLoadFile(txtPlain); }
    void OnLoadCipherFile(wxCommandEvent&) { HandleLoadFile(txtCipherInput); }
    void OnLoadKey(wxCommandEvent&) { HandleLoadFile(txtDecryptKey); }
    void OnSaveEncResult(wxCommandEvent&) { HandleSaveFile(txtCipherOutput->GetValue()); }
    void OnSaveDecResult(wxCommandEvent&) { HandleSaveFile(txtPlainOutput->GetValue()); }
    
    void OnSaveKey(wxCommandEvent&) { 
        wxString targetKey = txtEncryptKey->GetValue();
        if(targetKey.IsEmpty()) targetKey = txtDecryptKey->GetValue();
        HandleSaveFile(targetKey);
    }

    void OnCopyEncrypt(wxCommandEvent&)
    {
        if(txtCipherOutput->GetValue().IsEmpty()) {
            wxMessageBox(wxString::FromUTF8("Không có dữ liệu mật mã để sao chép!"), wxString::FromUTF8("Thất bại"), wxOK | wxICON_WARNING);
            return;
        }
        if(wxTheClipboard->Open()) {
            wxTheClipboard->SetData(new wxTextDataObject(txtCipherOutput->GetValue()));
            wxTheClipboard->Close();
            wxMessageBox(wxString::FromUTF8("Đã sao chép chuỗi mật mã vào bộ nhớ đệm thành công!"), wxString::FromUTF8("Thành công"), wxOK | wxICON_INFORMATION);
            SetStatusText(wxString::FromUTF8("Thông báo: Đã copy chuỗi mật mã."), 0);
        }
    }

    void OnCopyDecrypt(wxCommandEvent&)
    {
        if(txtPlainOutput->GetValue().IsEmpty()) {
            wxMessageBox(wxString::FromUTF8("Không có dữ liệu văn bản để sao chép!"), wxString::FromUTF8("Thất bại"), wxOK | wxICON_WARNING);
            return;
        }
        if(wxTheClipboard->Open()) {
            wxTheClipboard->SetData(new wxTextDataObject(txtPlainOutput->GetValue()));
            wxTheClipboard->Close();
            wxMessageBox(wxString::FromUTF8("Đã sao chép văn bản giải mã vào bộ nhớ đệm thành công!"), wxString::FromUTF8("Thành công"), wxOK | wxICON_INFORMATION);
            SetStatusText(wxString::FromUTF8("Thông báo: Đã copy văn bản giải mã."), 0);
        }
    }

    void OnClearEncrypt(wxCommandEvent&) {
        txtPlain->Clear(); txtEncryptKey->Clear(); txtCipherOutput->Clear();
        wxMessageBox(wxString::FromUTF8("Đã dọn sạch vùng dữ liệu cột Mã hóa!"), wxString::FromUTF8("Thông báo"), wxOK | wxICON_INFORMATION);
        SetStatusText(wxString::FromUTF8("Đã xóa dữ liệu cột Mã hóa."), 0);
    }

    void OnClearDecrypt(wxCommandEvent&) {
        txtCipherInput->Clear(); txtDecryptKey->Clear(); txtPlainOutput->Clear();
        wxMessageBox(wxString::FromUTF8("Đã dọn sạch vùng dữ liệu cột Giải mã!"), wxString::FromUTF8("Thông báo"), wxOK | wxICON_INFORMATION);
        SetStatusText(wxString::FromUTF8("Đã xóa dữ liệu cột Giải mã."), 0);
    }
};

class DESApp : public wxApp
{
public:
    virtual bool OnInit()
    {
        srand(time(NULL));
        DESAppFrame* frame = new DESAppFrame();
        frame->Show(true);
        return true;
    }
};

wxIMPLEMENT_APP(DESApp);