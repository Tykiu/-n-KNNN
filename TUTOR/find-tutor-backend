from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
import supabase

app = FastAPI()

# Kết nối Supabase
url = "https://YOUR_PROJECT.supabase.co"
key = "YOUR_SUPABASE_KEY"
supabase_client = supabase.create_client(url, key)

# Model cho request
class TutorRequest(BaseModel):
    subject: str
    mode: str   # "online" hoặc "offline"
    link_or_address: str
    time: str
    note: str | None = None

# API: Lấy danh sách yêu cầu tìm gia sư
@app.get("/tutor-requests")
def get_tutor_requests():
    response = supabase_client.table("tutor_requests").select("*").execute()
    return response.data

# API: Tạo yêu cầu tìm gia sư
@app.post("/tutor-requests")
def create_tutor_request(request: TutorRequest, user_id: str):
    data = {
        "user_id": user_id,
        "subject": request.subject,
        "mode": request.mode,
        "link_or_address": request.link_or_address,
        "time": request.time,
        "note": request.note,
        "verified": True  # giả sử user đã xác thực
    }
    response = supabase_client.table("tutor_requests").insert(data).execute()
    return response.data

# API: Xem chi tiết yêu cầu
@app.get("/tutor-requests/{request_id}")
def get_tutor_request_detail(request_id: str):
    response = supabase_client.table("tutor_requests").select("*").eq("id", request_id).execute()
    if not response.data:
        raise HTTPException(status_code=404, detail="Tutor request not found")
    return response.data[0]

# API: Xóa yêu cầu (khi đã đủ người)
@app.delete("/tutor-requests/{request_id}")
def delete_tutor_request(request_id: str):
    response = supabase_client.table("tutor_requests").delete().eq("id", request_id).execute()
    return {"message": "Tutor request deleted"}
