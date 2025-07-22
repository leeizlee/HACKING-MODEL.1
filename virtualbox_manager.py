#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VirtualBox 가상머신 관리자
"""

import subprocess
import json
import time
import re
from typing import Dict, List, Optional

class VirtualBoxManager:
    """VirtualBox 가상머신 관리자"""
    
    def __init__(self):
        self.vboxmanage_path = "VBoxManage"
        
    def get_vm_list(self) -> List[Dict]:
        """가상머신 목록 조회"""
        try:
            result = subprocess.run([self.vboxmanage_path, "list", "vms"], 
                                  capture_output=True, text=True)
            
            vms = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    # "VM Name" {uuid} 형식 파싱
                    match = re.match(r'"([^"]+)"\s+\{([^}]+)\}', line)
                    if match:
                        vm_name, vm_uuid = match.groups()
                        vm_info = self.get_vm_info(vm_name)
                        vms.append(vm_info)
                        
            return vms
            
        except Exception as e:
            print(f"VM 목록 조회 실패: {e}")
            return []
            
    def get_vm_info(self, vm_name: str) -> Dict:
        """가상머신 정보 조회"""
        try:
            result = subprocess.run([self.vboxmanage_path, "showvminfo", vm_name], 
                                  capture_output=True, text=True)
            
            info = {
                "name": vm_name,
                "uuid": "",
                "state": "unknown",
                "os": "unknown",
                "memory": "0",
                "cpu_count": "0"
            }
            
            for line in result.stdout.split('\n'):
                if "UUID:" in line:
                    info["uuid"] = line.split("UUID:")[1].strip()
                elif "State:" in line:
                    info["state"] = line.split("State:")[1].strip()
                elif "Guest OS:" in line:
                    info["os"] = line.split("Guest OS:")[1].strip()
                elif "Memory size:" in line:
                    info["memory"] = line.split("Memory size:")[1].strip()
                elif "Number of CPUs:" in line:
                    info["cpu_count"] = line.split("Number of CPUs:")[1].strip()
                    
            return info
            
        except Exception as e:
            print(f"VM 정보 조회 실패: {e}")
            return {"name": vm_name, "state": "unknown"}
            
    def start_vm(self, vm_name: str) -> bool:
        """가상머신 시작"""
        try:
            result = subprocess.run([self.vboxmanage_path, "startvm", vm_name], 
                                  capture_output=True, text=True)
            return result.returncode == 0
            
        except Exception as e:
            print(f"VM 시작 실패: {e}")
            return False
            
    def stop_vm(self, vm_name: str) -> bool:
        """가상머신 중지"""
        try:
            result = subprocess.run([self.vboxmanage_path, "controlvm", vm_name, "poweroff"], 
                                  capture_output=True, text=True)
            return result.returncode == 0
            
        except Exception as e:
            print(f"VM 중지 실패: {e}")
            return False
            
    def pause_vm(self, vm_name: str) -> bool:
        """가상머신 일시정지"""
        try:
            result = subprocess.run([self.vboxmanage_path, "controlvm", vm_name, "pause"], 
                                  capture_output=True, text=True)
            return result.returncode == 0
            
        except Exception as e:
            print(f"VM 일시정지 실패: {e}")
            return False
            
    def resume_vm(self, vm_name: str) -> bool:
        """가상머신 재개"""
        try:
            result = subprocess.run([self.vboxmanage_path, "controlvm", vm_name, "resume"], 
                                  capture_output=True, text=True)
            return result.returncode == 0
            
        except Exception as e:
            print(f"VM 재개 실패: {e}")
            return False
            
    def reset_vm(self, vm_name: str) -> bool:
        """가상머신 재시작"""
        try:
            result = subprocess.run([self.vboxmanage_path, "controlvm", vm_name, "reset"], 
                                  capture_output=True, text=True)
            return result.returncode == 0
            
        except Exception as e:
            print(f"VM 재시작 실패: {e}")
            return False
            
    def get_vm_ip(self, vm_name: str) -> Optional[str]:
        """가상머신 IP 주소 조회"""
        try:
            result = subprocess.run([self.vboxmanage_path, "guestproperty", "get", vm_name, "/VirtualBox/GuestInfo/Net/0/V4/IP"], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                ip = result.stdout.strip()
                if ip and ip != "No value set!":
                    return ip
                    
            return None
            
        except Exception as e:
            print(f"VM IP 조회 실패: {e}")
            return None
            
    def create_vm(self, vm_name: str, os_type: str, memory_mb: int = 1024, cpu_count: int = 1) -> bool:
        """가상머신 생성"""
        try:
            # VM 생성
            result = subprocess.run([self.vboxmanage_path, "createvm", "--name", vm_name, "--ostype", os_type], 
                                  capture_output=True, text=True)
            
            if result.returncode != 0:
                return False
                
            # 메모리 설정
            subprocess.run([self.vboxmanage_path, "modifyvm", vm_name, "--memory", str(memory_mb)], 
                         capture_output=True, text=True)
            
            # CPU 설정
            subprocess.run([self.vboxmanage_path, "modifyvm", vm_name, "--cpus", str(cpu_count)], 
                         capture_output=True, text=True)
            
            return True
            
        except Exception as e:
            print(f"VM 생성 실패: {e}")
            return False
            
    def delete_vm(self, vm_name: str) -> bool:
        """가상머신 삭제"""
        try:
            result = subprocess.run([self.vboxmanage_path, "unregistervm", vm_name, "--delete"], 
                                  capture_output=True, text=True)
            return result.returncode == 0
            
        except Exception as e:
            print(f"VM 삭제 실패: {e}")
            return False
            
    def test_connection(self, vm_name: str, port: int = 22) -> bool:
        """연결 테스트"""
        ip = self.get_vm_ip(vm_name)
        if not ip:
            return False
            
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
            
        except Exception as e:
            print(f"연결 테스트 실패: {e}")
            return False
            
    def ping_test(self, vm_name: str) -> bool:
        """Ping 테스트"""
        ip = self.get_vm_ip(vm_name)
        if not ip:
            return False
            
        try:
            result = subprocess.run(["ping", "-c", "1", ip], 
                                  capture_output=True, text=True)
            return result.returncode == 0
            
        except Exception as e:
            print(f"Ping 테스트 실패: {e}")
            return False