import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import evaluate

GT = [(100.0, "UNAUTHORIZED_FC"), (106.0, "REGISTER_ENUMERATION"),
      (109.0, "SENSITIVE_REGISTER_WRITE"), (112.0, "UNAUTHORIZED_CLIENT")]

def test_all_detected():
    notices = [(100.1, "ModbusWatch::Unauthorized_Function_Code"),
               (106.1, "ModbusWatch::Register_Enumeration"),
               (109.1, "ModbusWatch::Sensitive_Register_Write"),
               (112.1, "ModbusWatch::Unauthorized_Client")]
    _, detected, fp = evaluate.grade(GT, notices)
    assert detected == 4 and fp == 0

def test_missing_detection_is_caught():
    _, detected, fp = evaluate.grade(GT, [])
    assert detected == 0

def test_false_positive_is_counted():
    notices = [(100.1, "ModbusWatch::Unauthorized_Function_Code"),
               (500.0, "ModbusWatch::Register_Enumeration")]
    _, detected, fp = evaluate.grade([(100.0, "UNAUTHORIZED_FC")], notices)
    assert detected == 1 and fp == 1
