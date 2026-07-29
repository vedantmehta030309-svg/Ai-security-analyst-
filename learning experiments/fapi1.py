from fastapi import FastAPI,Path,HTTPException
#path is used to improve the readability of parameters
app = FastAPI()
import json


def load_Data():
    with open("patients.json",'r') as f:
        data = json.load(f)
    return data

@app.get("/view")
def view():
    data = load_Data()
    return data

@app.get("/")
def hello():
    return {"message":"patient mgt system ig"}

@app.get("/about")
def about():
    return "just a sexy guy who is somehow single ;)"

@app.get("/patients/{patient_id}")
def view_patient(patient_id : str = Path(...,description = 'ID of patients in DB' , example = 'P001')):
    data = load_Data()
    if patient_id in data:
        return data[patient_id]
    raise HTTPException(status_code=404,detail="patient not found")

