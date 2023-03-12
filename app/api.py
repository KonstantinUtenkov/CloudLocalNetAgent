from fastapi import FastAPI, Header
from fastapi.middleware.cors import CORSMiddleware
from pysondb import db
import cpuinfo
from typing import Union
import uuid
import requests
import json
import re
import time

import traceback
import subprocess
import os
import platform
import threading


import logging
FORMAT = "%(levelname)s:%(message)s"
logging.basicConfig(format=FORMAT, level=logging.DEBUG)
log = logging.getLogger("app")


import time

from subprocess import Popen, PIPE

from pydantic import BaseModel

class Action(BaseModel):
    host_id: Union[str, None] = None
    ip_addr: Union[str, None] = None
    action_id: Union[str, None] = None

a=db.getDb("/mnt/host/db.json")

AGENT_PORT="7190"

#Make host_id and add to file DB or find already known
try:
    q = {"key": "host_id"}
    host_uuid=a.getByQuery(query=q)
    #print(host_uuid)
    if len(host_uuid) == 0:
        HOST_UUID=str(uuid.uuid4())
        a.add({"value":HOST_UUID,"key":"host_id"})
    else:
        HOST_UUID=host_uuid[0]["value"]
except Exception as inst:
    print(inst)
    HOST_UUID=str(uuid.uuid4())
    a.add({"value":HOST_UUID,"key":"host_id"})

print (HOST_UUID)

HOST_CORES = cpuinfo.get_cpu_info()["count"]
meminfo = dict((i.split()[0].rstrip(':'),int(i.split()[1])) for i in open('/proc/meminfo').readlines())
mem_kib = meminfo['MemTotal']
HOST_MEM = round(mem_kib/1024/1024,1)

#BACK="http://192.168.1.55:8000"
#BACK="http://dev.cloudlocalnet.com:8000"
BACK="https://dev.cloudlocalnet.com"

vms = [
    {
        "id": "1",
        "item": "Fake test VM"
    },
    {
        "id": "2",
        "item": "Fake 2 test VM"
    }
]


stdout, stderr = Popen(['rm', '/root/.ssh/forward.id_rsa'], stdout=PIPE, stderr=PIPE).communicate()
stdout, stderr = Popen(['rm', '/root/.ssh/forward.id_rsa.pub'], stdout=PIPE, stderr=PIPE).communicate()
stdout, stderr = Popen(['ssh-keygen', '-f', '/root/.ssh/forward.id_rsa', '-N', '\'\''], stdout=PIPE, stderr=PIPE).communicate()
#full_stdout += str(stdout.decode('utf-8'))
#full_stderr += str(stderr.decode('utf-8'))


f = open("/root/.ssh/forward.id_rsa.pub", "r")
PUBLIC_KEY_HOST=f.read()
f.close()

app = FastAPI()

origins = [
    "*"
]


app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        #allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"]
)


def register_port(proxy_addr, proxy_external_addr, proxy_external_port, proxy_internal_port):
#proxy_addr - Внешний адрес прокси-сервер, к которому коннектиться
#proxy_external_addr - Адрес на прокси-сервере, НА который будет вывешиваться порт
#proxy_external_port - Номер порта НА который будет прокситься порт
#proxy_internal_port - Номер порта который будет проксится
#ssh -N -R 20000:localhost:80 -o ServerAliveInterval=10 -o ExitOnForwardFailure=yes forward@192.168.1.116 -p 22 -i ~/.ssh/id_rsa
#ssh -N -R 20000:localhost:80 -o ServerAliveInterval=10 -o ExitOnForwardFailure=yes forward@192.168.1.116 -p 22 -i ~/.ssh/id_rsa
    print("regestry port")
    log.info("%s %s %s %s "%(proxy_addr, proxy_external_addr, proxy_external_port, proxy_internal_port))
    try:
        while True:
            #stdout, stderr = Popen(['git', '-c', 'http.sslVerify=false', 'clone', str(action["source"]), '/mnt/action/'+ str(action["id"])], stdout=PIPE, stderr=PIPE).communicate(timeout=source_timeout)
            stdout, stderr = Popen(['ssh', '-N', '-R', proxy_external_port+':'+proxy_external_addr+':'+proxy_internal_port,  '-o', 'ServerAliveInterval=10', '-o', 'ExitOnForwardFailure=yes', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=no', 'forward@'+proxy_addr, '-p', '22', '-i', '/root/.ssh/forward.id_rsa'], stdout=PIPE, stderr=PIPE).communicate()
            log.info(str(stdout.decode('utf-8')))
            log.info(str(stderr.decode('utf-8')))
            time.sleep(10)
    except Exception as inst:
        allowedExecution=True
        print(inst)
    return


# Зарегистрировать порт самого агента на прокси(делается каждый раз, когда агент рестартует и на новый ключ и на новый порт)
# Запрашиваем адрес и порт для проксирования порта 7190. То есть порт 7190 хоста агента будет проксироваться на указанный прокси сервер на указанные адрес и порт
while True:
    AUTHORIZED_USER=""
    try:
        q = {"key": "authorized_user"}
        auth_users=a.getByQuery(query=q)
        if len(auth_users) == 0:
            #a.add({"value":str(user_id),"key":"authorized_user"})
            AUTHORIZED_USER=""
        else:
            AUTHORIZED_USER=auth_users[0]["value"]
    except Exception as inst:
        AUTHORIZED_USER=""
        print(inst)
    
    register_headers = {"Content-Type": "application/json"}
    register_data={"host_id":HOST_UUID, "authorized_user":AUTHORIZED_USER, "host_key":PUBLIC_KEY_HOST}
    response = requests.post("%s/back/register-agent"%BACK, headers=register_headers, json=register_data)
    print("Status Code", response.status_code)
    print("JSON Response ", response.json())


    #if 'action_timeout' in action.keys():
    if 'proxy_addr' in response.json().keys() and 'proxy_ext_addr' in response.json().keys() and 'proxy_ext_port' in response.json():
        break
    
    time.sleep(60)


#Запуск регистрации порта
log.info(str(response.json()["proxy_addr"]))
log.info(str(response.json()["proxy_ext_addr"]))
log.info(str(response.json()["proxy_ext_port"]))
log.info(str(AGENT_PORT))

register_thread = threading.Thread(target=register_port, name="Proxyng port", args=(response.json()["proxy_addr"],response.json()["proxy_ext_addr"],response.json()["proxy_ext_port"],AGENT_PORT), daemon=True)
register_thread.start()
#register_port(response.json()["proxy_addr"],response.json()["proxy_ext_addr"],response.json()["proxy_ext_port"],AGENT_PORT)


# Запуск проксирования сохраненных портов(то есть надо запросить список сохраненных портов и их запроксировать)

async def action_execute(action):
    print("execute action %s"%action)

    full_stdout = ""
    full_stderr = ""

    #if (action["action_timeout"]):
    if 'action_timeout' in action.keys():
        action_timeout=int(action["action_timeout"])
    else:
        action_timeout=int(255)

    #if (action["source_timeout"]):
    if 'source_timeout' in action.keys():
        source_timeout=int(action["source_timeout"])
    else:
        source_timeout=int(255)


    print(source_timeout, action_timeout)

    #Clone action repository(Auth type: None, http_pass, ssh_key)
    print("Clear directory for action")
    #stdout, stderr = Popen(['rm', '-r', '/mnt/action/'+ str(action["id"])], stdout=PIPE, text=True).communicate()
    stdout, stderr = Popen(['rm', '-r', '/mnt/action/'+ str(action["id"])], stdout=PIPE, stderr=PIPE).communicate()
    #full_stdout += str(stdout.decode('utf-8').splitlines())
    full_stdout += str(stdout.decode('utf-8'))
    full_stderr += str(stderr.decode('utf-8'))

    print("clone action from source %s"%action["source"])
    #stdout, stderr = Popen(['git', '-c', 'http.sslVerify=false', 'clone', str(action["source"]), '/mnt/action/'+ str(action["id"])], stdout=PIPE, text=True).communicate()
    stdout, stderr = Popen(['git', '-c', 'http.sslVerify=false', 'clone', str(action["source"]), '/mnt/action/'+ str(action["id"])], stdout=PIPE, stderr=PIPE).communicate(timeout=source_timeout)
    full_stdout += str(stdout.decode('utf-8'))
    full_stderr += str(stderr.decode('utf-8'))

    print("Set branch action from source %s"%action["branch"])
    #stdout_gitcheckout, stderr_gitcheckout = Popen(['cd','/mnt/action/'+ str(action["id"]),'&&', 'git checkout ' + str(action["branch"])], stdout=PIPE).communicate()
    stdout, stderr = Popen(['git','checkout' , str(action["branch"])], stdout=PIPE, cwd='/mnt/action/'+ str(action["id"]), stderr=PIPE).communicate()
    full_stdout += str(stdout.decode('utf-8'))
    full_stderr += str(stderr.decode('utf-8'))

    print("execute action %s"%action)
    stdout, stderr = Popen(['/mnt/action/' + str(action["id"]) + "/"+ str(action["source_path"]) + str(action["source_run_file"])], stdout=PIPE, stderr=PIPE).communicate(timeout=action_timeout)
    #print(str(stdout.decode('utf-8')))
    #print(str(stderr.decode('utf-8')))

    full_stdout += str(stdout.decode('utf-8'))
    full_stderr += str(stderr.decode('utf-8'))

    print(full_stdout, full_stderr)

    #print(stdout_clear, stderr_clear, stdout_gitclone, stderr_gitclone, stdout_gitcheckout, stderr_gitcheckout, stdout_runaction, stderr_runaction)
    #full_output = stdout_clear + stderr_clear + stdout_gitclone + stderr_gitclone + stdout_gitcheckout + stderr_gitcheckout + stdout_runaction + stderr_runaction
    #full_output = full_output
    #full_output = json.dumps(str(stdout_clear) + str(stderr_clear) + str(stdout_gitclone) + str(stderr_gitclone) + str(stdout_gitcheckout) + str(stderr_gitcheckout) + str(stdout_runaction) + str(stderr_runaction)).replace('"', "'")

    #full_output = json.dumps((full_stdout + full_stderr).replace('"', "'"))
    #full_output = (full_stdout + full_stderr).replace('"', "'")
    #full_output = (full_stdout + full_stderr).replace('"', "'")
    full_stdout = full_stdout.replace('"', "'")
    full_stderr = full_stderr.replace('"', "'")
    return full_stdout, full_stderr

@app.get("/", tags=["root"])
async def read_root() -> dict:
    return {"message": "Welcome to VM list"}

@app.get("/ping", tags=["ping"])
async def ping_root(authorization: Union[str, None] = Header(default=None)):
    #print("Authorization: %s"%authorization)
    #headers = {"Authorization": authorization}
    #data ={}
    #response = requests.get("%s/users/me"%BACK, headers=headers, json=data)
    #print("Status Code", response.status_code)
    #print("JSON Response ", response.json())
    try:
        q = {"key": "host_id"}
        host_id=a.getByQuery(query=q)[0]["value"]
    except:
        host_id="error"
    try:
        q = {"key": "authorized_user"}
        authorized_user=a.getByQuery(query=q)[0]["value"]
    except:
        authorized_user=None

    #return {"Bearer": authorization}
    return {"host_id": host_id, "cores":HOST_CORES, "mem":HOST_MEM, "authorized_user":authorized_user}




@app.get("/bind", tags=["bind"])
async def bind_host(authorization: Union[str, None] = Header(default=None)):
    print("Authorization: %s"%authorization)
    headers = {"Authorization": authorization}
    data ={}
    response = requests.get("%s/users/me"%BACK, headers=headers, json=data)
    print("Status Code", response.status_code)
    print("JSON Response ", response.json())
    try:
        user_id = response.json()["id"]
        print(user_id)
        try:
            q = {"key": "authorized_user"}
            auth_users=a.getByQuery(query=q)
            if len(auth_users) == 0:
                a.add({"value":str(user_id),"key":"authorized_user"})
                return {"Detail": "Success binded"}
            else:
                return {"Detail":"Already binded"}
        except Exception as inst:
            print(inst)
    except:
        print("Detail:Unauthorized")
        return {"Detail":"Unauthorized"}
    return {"Detail":"Unauthorized"}

@app.get("/unbind", tags=["bind"])
async def unbind_host(authorization: Union[str, None] = Header(default=None)):
    print("Authorization: %s"%authorization)
    headers = {"Authorization": authorization}
    data ={}
    response = requests.get("%s/users/me"%BACK, headers=headers, json=data)
    print("Status Code", response.status_code)
    print("JSON Response ", response.json())
    try:
        user_id = response.json()["id"]
        print(user_id)
        try:
            q = {"key": "authorized_user"}
            auth_users=a.getByQuery(query=q)
            if len(auth_users) == 0:
                #a.add({"value":str(user_id),"key":"authorized_user"})
                return {"Detail": "Already Unbinded"}
            else:
                if auth_users[0]["value"] == user_id :
                    print(auth_users)
                    record_id=a.getByQuery(query=q)[0]["id"]
                    is_deleted = a.deleteById(pk=record_id)
                    print(is_deleted)
                    return {"Detail":"Success Unbinded"}
                else:
                    print("User does not match")
                    return {"Detail":"User dos not match"}
        except Exception as inst:
            print(inst)
    except:
        print("Detail:Unauthorized")
        return {"Detail":"Unauthorized"}
    return {"Detail":"Unauthorized"}


@app.post("/action/", tags=["action"])
#async def start_action(authorization: Union[str, None] = Header(default=None), action: Action):
async def start_action(action: Action, authorization: Union[str, None] = Header(default=None)):
    print("Authorization: %s"%authorization)
    headers = {"Content-Type": "application/json", "Authorization": authorization}
    data ={}
    response = requests.get("%s/users/me"%BACK, headers=headers, json=data)
    print("Status Code", response.status_code)
    print("JSON Response ", response.json())

    try:
        user_id = response.json()["id"]
        print(user_id)
    except Exception as inst:
        print("Except %s (Unuthorized)"%inst)
        user_id=""
    try:
        q = {"key": "authorized_user"}
        auth_users=a.getByQuery(query=q)
        if len(auth_users) == 0:
            allowedExecution=True
        else:
            if auth_users[0]["value"] == user_id :
                allowedExecution=True
            else:
                allowedExecution=False
    except Exception as inst:
        allowedExecution=True
        print(inst)
    if allowedExecution==True:
        data={"host_id":action.host_id, "ip_addr": action.ip_addr, "action_id": action.action_id}
        print("DATA: %s"%data)
        response_action = requests.post("%s/action"%BACK, headers=headers, json=data)
        print("Status Code", response_action.status_code)
        print("JSON Response ", response_action.json())
        full_stdout, full_stderr = await action_execute(response_action.json())
        return {"Detail":"Execute action", "full_stdout": full_stdout, "full_stderr": full_stderr}
    else:
        return {"Detail":"Execute action denied"}
        

@app.get("/cpuinfo", tags=["cpuinfo"])
async def cpu_info():
    return {"cpuinfo": cpuinfo.get_cpu_info()}


@app.get("/vm", tags=["vms"])
async def get_vms() -> dict:
    print("Get vms:%s"%vms)
    return { "data": vms }


@app.post("/vm", tags=["vms"])
async def add_vm(vm: dict) -> dict:
    vms.append(vm)
    print("Add vm:%s"%vms)
    return {
        "data": { "VM added." }
    }


@app.put("/vm/{id}", tags=["vms"])
async def update_vm(id: int, body: dict) -> dict:
    for vm in vms:
        if int(vm["id"]) == id:
            vm["item"] = body["item"]
            print("Update VMs:%s"%vms)
            return {
                "data": f"VM with id {id} has been updated."
            }

    print("Update VMs:%s"%vms)
    return {
        "data": f"VM with id {id} not found."
    }


@app.delete("/vm/{id}", tags=["vms"])
async def delete_vm(id: int) -> dict:
    for vm in vms:
        if int(vm["id"]) == id:
            vms.remove(todo)
            print("Remove VMs:%s"%vms)
            return {
                "data": f"VM with id {id} has been removed."
            }

    print("Update VMs:%s"%vms)
    return {
        "data": f"VM with id {id} not found."
    }
