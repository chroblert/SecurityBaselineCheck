<#
Author: JC (@chroblert)
Author: JC0o0l (@chroblert)
Mail: jerryzvs@163.com
wechat: Chroblert_Jerrybird(信安札记)
#>
chcp 65001
function Get-BasicInfo{
	$hostname = hostname
	Write-Host $hostname
	$ipList = ""
	$macaddr = ""
	foreach($line in ipconfig /all|Select-String -Pattern "^\s*IPv4"){ 
		$line=$line.ToString().split(":")[1].replace("(","\(").replace(")","\)")
		$context = (ipconfig /all |Select-String -Pattern $line -Context 6,0).Context[0]
		if ($context.Precontext|Select-String "VMware" -Quiet){
			continue	
		}
		foreach ($lline in $context.Precontext.split("\n")){
			#Write-Host $lline
			if ($lline.ToString().contains("Physical")){
				#Write-Host $lline.ToString() dddd
				$macaddr = $macaddr + $lline.ToString().split(":")[1].Trim() + ";"
				break
			}
		}
		$ipList = $ipList + $line.ToString().split("\")[0].trim() + ";"
	}
	Write-Host hostname:$hostname
	Write-Host macaddr: $macaddr 
	Write-Host ipList : $ipList 
}
function Get-SecInfo{
	$secinfo=""
	SecEdit.exe /export /cfg sec.inf 
	$secInfoArray=Get-Content .\sec.inf
	foreach ($line in $secInfoArray){
		$secinfo = $secinfo + $line.ToString() + ";"
	}
	return $secInfoArray
}
function Check-PasswordPolicy{
	<#
	.SYNOPSIS
	检查密码策略是否符合预定策略

	.DESCRIPTION
	预定策略：
		密码历史：5
		密码最长使用期限：90
		密码最短使用期限：1
		密码复杂度是否开启：1开启
		是否以可还原的方式加密存储密码：0否
		密码最小长度：8位
	.EXAMPLE
	Check-PasswordPolicy secInfoArray

	.NOTES
	General notes
	#>
	Param(
		[System.Collections.ArrayList]$secInfoArray
	)
	$stPasswordHistorySize=5
	$stMaximumPasswordAge=90
	$stMinimumPasswordAge=1
	$stPasswordComplexity=1
	$stClearTextPassword=0
	$stMinimumPasswordLength=8
	$passwordHistorySize=(Write-Output $secInfoArray|Select-String -pattern "^PasswordHistorySize").ToString().Split("=")[1] -replace "\s",""
	if($passwordHistorySize -lt $stPasswordHistorySize){
		Write-Host [-] PasswordHistorySize less than $stPasswordHistorySize -ForegroundColor Red
	}
	$maximumPasswordAge=(Write-Output $secInfoArray|Select-String -Pattern "^MaximumPasswordAge" ).ToString().Split("=")[1]  -replace "\s",""
	if($maximumPasswordAge -lt $stMaximumPasswordAge){
		Write-Host [-] MaximumPasswordAge less than $stMaximumPasswordAge -ForegroundColor Red
	}
	$minimumPasswordAge=(Write-Output $secInfoArray|Select-String -Pattern "^MinimumPasswordAge").ToString().Split("=")[1] -replace "\s",""
	if($minimumPasswordAge -lt $stMinimumPasswordAge){
		Write-Host [-] MinimumPasswordAge less than $stMinimumPasswordAge -ForegroundColor Red
	}
	$passwordComplexity=(Write-Output $secInfoArray|Select-String -Pattern "^PasswordComplexity").ToString().Split("=")[1] -replace "\s",""
	if($passwordComplexity -ne $stPasswordComplexity){
		Write-Host [-] PasswordComplexity value is not $stPasswordComplexity -ForegroundColor Red
	}
	$clearTextPassword=(Write-Output $secInfoArray|Select-String -Pattern "^ClearTextPassword").ToString().Split("=")[1] -replace "\s",""
	if($clearTextPassword -ne $stClearTextPassword){
		Write-Host [-] ClearTextPassword value is not stCclearTextPassword -ForegroundColor Red
	}
	$minimumPasswordLength=(Write-Output $secInfoArray|Select-String -Pattern "^MinimumPasswordLength").ToString().Split("=")[1] -replace "\s",""
	if($minimumPasswordLength -lt $stMinimumPasswordLength){
		Write-Host MinimumPasswordLength less than $stMinimumPasswordLength -ForegroundColor Red
	}
	$password_check_info="{""passwordHistorySize"":""$passwordHistorySize"",""maximumPasswordAge"":""$maximumPasswordAge"",""minimumPasswordAge"":$minimumPasswordAge"",""passwordComplexity"":""$passwordComplexity"",""clearTextPassword"":""$clearTextPassword"",""minimumPasswordLength"":""$minimumPasswordLength""}"
	#Write-Host $password_check_info
	return $password_check_info

}
function Check-AccountLockoutPolicy{
	<#
	.SYNOPSIS
	检查账户锁定的相关策略
	
	.DESCRIPTION
	预定策略：
		账户锁定时间：15 Or more
		账户锁定阈值: 5 or less
		重置账户锁定: 15 or more,但值要小于账户锁定时间
	
	.PARAMETER secInfoArray
	使用secedit /export /cfg sec.inf 导出的文件，再输出到secInfoArray中

	.EXAMPLE
	Check-AccountLockoutPolicy $secInfoArray
	
	.NOTES
	General notes
	#>
	
	Param(
		[System.Collections.ArrayList]$secInfoArray
	)
	$stLockoutDuration=15
	$stLockoutBadCount=5
	$stResetLockoutCount=15
	$lockoutDuration=(Write-Output $secInfoArray|Select-String -Pattern "^LockoutDuration").ToString().Split("=")[1] -replace "\s",""
	if($lockoutDuration -lt $stLockoutDuration){
		Write-Host [-] LockoutDuration less than $stLockoutDuration -ForegroundColor Red
	}
	$lockoutBadCount=(Write-Output $secInfoArray|Select-String -Pattern "^LockoutBadCount").ToString().Split("=")[1] -replace "\s",""
	if($lockoutBadCount -lt $stLockoutBadCount){
		Write-Host [-] LockoutBadCount less than $stLockoutBadCount -ForegroundColor Red
	}
	$resetLockoutCount=(Write-Output $secInfoArray|Select-String -Pattern "^ResetLockoutCount").ToString().Split("=")[1] -replace "\s",""
	if($resetLockoutCount -lt $stLockoutDuration -or  $resetLockoutCount -gt $lockoutDuration){
		Write-Host [-] ResetLockoutCount great than $stResetLockoutCount or less than $stLockoutDuration
	}
	$account_lockout_info="{""lockoutDuration"":""$lockoutDuration"",""lockoutBadCount"":""$lockoutBadCount"",""resetLockoutCount"":""$resetLockoutCount""}"
	return $account_lockout_info


}
function Get-AccountPolicyCheckRes{
	Param(
		[System.Collections.ArrayList] $secInfoArray
	)
	$password_check_info=(Check-PasswordPolicy $secInfoArray)
	$account_lockout_info=(Check-AccountLockoutPolicy $secInfoArray)
	$account_check_res="{""password_check_info"":$password_check_info,""account_lockout_info"":$account_lockout_info}"
	return $account_check_res
}
function  Get-AuditPolicyCheckRes {
	<#
	.SYNOPSIS
     获取策略中关于审计策略的部分
	
	.DESCRIPTION
	预定策略：
		 审核策略更改：成功
		 审核登录事件：成功，失败
		 审核对象访问：成功
		 审核进程跟踪：成功，失败
		 审核目录服务访问：成功，失败
		 审核系统事件：成功，失败
		 审核账户登录事件：成功，失败
		 审核账户管理事件：成功，失败
	预设值的含义：
		0：没有开启审计
		1：审计成功事件
		2：审计失败事件
		3：审计成功和失败事件
	
	.PARAMETER secInfoArray
	Parameter description
	
	.EXAMPLE
	An example
	
	.NOTES
	General notes
	#>
	
	param (
		[System.Collections.ArrayList]$secInfoArray
	)

	$stAuditPolicyChange=1
	$stAuditLogonEvents=3
	$stAuditObjectAccess=1
	$stAuditProcessTracking=3
	$stAuditDSAccess=3
	$stAuditSystemEvents=3
	$stAuditAccountLogon=3
	$stAuditAccountManage=3
	$auditPolicyChange=(Write-Output $secInfoArray|Select-String -Pattern "^AuditPolicyChange").ToString().Split("=")[1] -replace "\s",""
	if($auditPolicyChange -lt $stAuditPolicyChange){
		Write-Host [-] AuditPolicyChange value should be $stAuditPolicyChange -ForegroundColor Red
	}
	$auditLogonEvents=(Write-Output $secInfoArray|Select-String -Pattern "^AuditLogonEvents").ToString().Split("=")[1] -replace "\s",""
	if($auditLogonEvents -lt $stAuditLogonEvents){
		Write-Host [-] AuditLogonEvents value should be $stAuditLogonEvents -ForegroundColor Red
	}
	$auditObjectAccess=(Write-Output $secInfoArray|Select-String -Pattern "^AuditObjectAccess").ToString().Split("=") -replace "\s",""
	if($auditObjectAccess -lt $stAuditObjectAccess){
		Write-Host [-] AuditObjectAccess value should be $stAuditObjectAccess -ForegroundColor Red
	}
	$auditProcessTracking=(Write-Output $secInfoArray|Select-String -Pattern "^AuditProcessTracking").ToString().Split("=") -replace "\s",""
	if($auditProcessTracking -lt $stAuditProcessTracking){
		Write-Host [-] AuditProcessTracking value should be $stAuditProcessTracking -ForegroundColor Red
	}
	$auditDSAccess=(Write-Output $secInfoArray|Select-String -Pattern "^AuditDSAccess").ToString().Split("=") -replace "\s",""
	if($auditDSAccess -lt $stAuditDSAccess){
		Write-Host [-] AuditDSAccess value should be $stAuditDSAccess -ForegroundColor Red
	}
	$auditSystemEvents=(Write-Output $secInfoArray|Select-String -Pattern "^AuditSystemEvents").ToString().Split("=") -replace "\s",""
	if($auditSystemEvents -lt $stAuditSystemEvents){
		Write-Host [-] AuditSystemEvents value should be $stAuditSystemEvents -ForegroundColor Red
	}
	$auditAccountLogon=(Write-Output $secInfoArray|Select-String -Pattern "^AuditAccountLogon").ToString().Split("=") -replace "\s",""
	if($auditAccountLogon -lt $stAuditAccountLogon){
		Write-Host [-] AuditAccountLogon value should be $stAuditAccountLogon -ForegroundColor Red
	}
	$auditAccountManage=(Write-Output $secInfoArray|Select-String -Pattern "^AuditAccountManage").ToString().Split("=") -replace "\s",""
	if($auditAccountManage -lt $stAuditAccountManage){
		Write-Host [-] AuditAccountManage value should be $stAuditAccountManage -ForegroundColor Red
	}
	$audit_check_res="{""auditPolicyChange"":""$auditPolicyChange"",""auditLogonEvents"":""$auditLogonEvents"",""auditObjectAccess"":""$auditObjectAccess"",""auditProcessTracking"":""$auditProcessTracking"",""auditDSAccess"":""$auditDSAccess"",""auditSystemEvents"":""$auditSystemEvents"",""auditAccountLogon"":""$auditAccountLogon"",""auditAccountManage"":""$auditAccountManage""}"
	#Write-Host $audit_check_res
	return $audit_check_res
	
}
function Get-UserRightPolicyCheckRes{
	Param(
		[System.Collections.ArrayList]$secInfoArray
	)
	# 确保“作为受信任的呼叫放访问凭据管理器”值为空
	$seTrustedCredManAccessPrivilege=(Write-Output $secInfoArray|Select-String -Pattern "^SeTrustedCredManAccessPrivilege" -Quiet) 
	if(-not $seTrustedCredManAccessPrivilege){
		$seTrustedCredManAccessPrivilegeIFNone="True"
	}else{
		$seTrustedCredManAccessPrivilegeIFNone=(Write-Output $secInfoArray|Select-String -Pattern "^SeTrustedCredManAccessPrivilege").ToString().Split("=")[1] -replace "\s",""
		Write-Host "[-] SeTrustedCredManAccessPrivilege value should be None" -ForegroundColor Red
	}
	# 确保“以操作系统方式运行”值为空
	$seTcbPrivilege=(Write-Output $secInfoArray|Select-String -Pattern "^SeTcbPrivilege" -Quiet) 
	if(-not $seTcbPrivilege){
		$seTcbPrivilegeIFNone="True"
	}else{
		$seTcbPrivilegeIFNone=(Write-Output $secInfoArray|Select-String -Pattern "^SeTcbPrivilege").ToString().Split("=")[1] -replace "\s",""
		Write-Host "[-] SeTcbPrivilege value should be None" -ForegroundColor Red
	}
	# 确保“将工作站添加到域”值仅为特定的几个用户，不得为域账户、guest账户及域计算机
	$seMachineAccountPrivilegeIFOnlySpecifiedUserOrArray=(Write-Output $secInfoArray|Select-String "^SeMachineAccountPrivilege" -Quiet)
	if(-not $seMachineAccountPrivilegeIFOnlySpecifiedUserOrArray){
		$seMachineAccountPrivilegeIFOnlySpecifiedUserOrArray="True"
	}else{
		$flag=0
		foreach($sid in ((Write-Output $secInfoArray|Select-String -Pattern "^SeMachineAccountPrivilege").ToString().Split("=")[1].Trim()).Split(",")){
			$sidSuffix=$sid.split("-")[-1].ToString()
			#Write-Host $sidSuffix
			$seMachineAccountPrivilegeIFOnlySpecifiedUserOrArray=$seMachineAccountPrivilegeIFOnlySpecifiedUserOrArray.ToString()+ $sidSuffix +";"
			if($sidSuffix.contains("513") -or $sidSuffix.contains("514") -or $sidSuffix.contains("515") -or $sidSuffix.contains("501")){
				$flag=1
			}
		} 
		if ($flag){
			Write-Host "[-] SeMachineAccountPrivilege value should only be specified user or group ,cannot be guest ,domain user or domain computer" -ForegroundColor Red
		}else{
			$seMachineAccountPrivilegeIFOnlySpecifiedUserOrArray="True"
		}
	}
	# 确保“创建全局对象”值为空
	$seCreateGlobalPrivilegeIFNone=(Write-Output $secInfoArray|Select-String -Pattern "^SeCreateGlobalPrivilege" -Quiet)
	if(-not $seCreateGlobalPrivilegeIFNone){
		$seCreateGlobalPrivilegeIFNone="True"
	}else{
		$seCreateGlobalPrivilegeIFNone=(Write-Output $secInfoArray|Select-String -Pattern "^SeCreateGlobalPrivilege" ).ToString().Split("=")[1] -replace "\s",""
		Write-Host "[-] SeCreateGlobalPrivilege value should be None" -ForegroundColor Red
	}
	# 确保“拒绝作为批处理作业登录”包含“Guests"
	$seDenyBatchLogonRightIFContainGuests=(Write-Output $secInfoArray|Select-String -Pattern "^SeDenyBatchLogonRight" -Quiet)
	if(-not $seDenyBatchLogonRightIFContainGuests){
		$seDenyBatchLogonRightIFContainGuests="False"
		Write-Host "[-] SeDenyBatchLogonRight value should contains 501(guest account)" -ForegroundColor Red
	}else{
		$flag=0
		foreach($sid in ((Write-Output $secInfoArray|Select-String -Pattern "^SeDenyBatchLogonRight").ToString().Split("=")[1].Trim()).Split(",")){
			$sidSuffix=$sid.Split("-")[-1].ToString()
			if($sidSuffix.Contains("501")){
				$seDenyBatchLogonRightIFContainGuests="True"
				$flag=1
			}
		}
		if(-not $flag){
			$seDenyBatchLogonRightIFContainGuests="False"
			Write-Host "[-] SeDenyBatchLogonRight value should contains 501(guest account)" -ForegroundColor Red
		}
	}
	# 确保”拒绝以服务身份登录”值包含“Guest”
	$seDenyServiceLogonRightIFContainGuests=(Write-Output $secInfoArray|Select-String -Pattern "^SeDenyServiceLogonRight" -Quiet)
	if(-not $seDenyServiceLogonRightIFContainGuests){
		$seDenyServiceLogonRightIFContainGuests="False"
		Write-Host "[-] SeDenyServiceLogonRight value should contains 501(guest account)" -ForegroundColor Red
	}else{
		$flag=0
		foreach($sid in ((Write-Output $secInfoArray|Select-String -Pattern "^SeDenyServiceLogonRight").ToString().Split("=")[1].Trim()).Split(",")){
			$sidSuffix=$sid.Split("-")[-1].ToString()
			if($sidSuffix.Contains("501")){
				$seDenyServiceLogonRightIFContainGuests="True"
				$flag=1
			}
		}
		if(-not $flag){
			$seDenyServiceLogonRightIFContainGuests="False"
			Write-Host "[-] SeDenyServiceLogonRight value should contains 501(guest account)" -ForegroundColor Red
		}
	}
	# 确保“拒绝本地登录”值包含“Guests”
	$seDenyInteractiveLogonRightIFContainGuests=(Write-Output $secInfoArray|Select-String -Pattern "^SeDenyInteractiveLogonRight" -Quiet)
	if(-not $seDenyInteractiveLogonRightIFContainGuests){
		$seDenyInteractiveLogonRightIFContainGuests="False"
		Write-Host "[-] SeDenyInteractiveLogonRight value should contains 501(guest account)" -ForegroundColor Red
	}else{
		$flag=0
		foreach($sid in ((Write-Output $secInfoArray|Select-String -Pattern "^SeDenyInteractiveLogonRight").ToString().Split("=")[1].Trim()).Split(",")){
			$sidSuffix=$sid.Split("-")[-1].ToString()
			if($sidSuffix.Contains("501")){
				$seDenyInteractiveLogonRightIFContainGuests="True"
				$flag=1
			}
		}
		if(-not $flag){
			$seDenyInteractiveLogonRightIFContainGuests="False"
			Write-Host "[-] SeDenyInteractiveLogonRight value should contains 501(guest account)" -ForegroundColor Red
		}
	}
	# 确保“从远程强制关机”值为“administrator”本地组s-1-5-32-544和“s-1-5-32-549”（域控的一个内置组）
	$seRemoteShutdownPrivilegeIFOnlySpecifiedUserOrArray=(Write-Output $secInfoArray|Select-String "^SeRemoteShutdownPrivilege" -Quiet)
	if(-not $seRemoteShutdownPrivilegeIFOnlySpecifiedUserOrArray){
		$seRemoteShutdownPrivilegeIFOnlySpecifiedUserOrArray="True"
	}else{
		$flag=0
		$count=0
		foreach($sid in ((Write-Output $secInfoArray|Select-String -Pattern "^SeRemoteShutdownPrivilege").ToString().Split("=")[1].Trim()).Split(",")){
			$count=$count+1
			$sidSuffix=$sid.split("-")[-1].ToString()
			#Write-Host $sidSuffix
			$seRemoteShutdownPrivilegeIFOnlySpecifiedUserOrArray=$seRemoteShutdownPrivilegeIFOnlySpecifiedUserOrArray.ToString()+ $sidSuffix +";"
			if($sidSuffix.contains("513") -or $sidSuffix.contains("514") -or $sidSuffix.contains("515") -or $sidSuffix.contains("501")){
				$flag=1
			}
		} 
		if ($flag -or $count -gt 2){
			Write-Host "[-] SeRemoteShutdownPrivilege value should only be specified user or group ,cannot be guest ,domain user or domain computer" -ForegroundColor Red
		}else{
			$seRemoteShutdownPrivilegeIFOnlySpecifiedUserOrArray="True"
		}
	}
	# 确保“修改对象标签”值为空
	$seRelabelPrivilegeIFNone=(Write-Output $secInfoArray|Select-String -Pattern "^SeRelabelPrivilege" -Quiet)
	if(-not $seRelabelPrivilegeIFNone){
		$seRelabelPrivilegeIFNone="True"
	}else{
		$seRelabelPrivilegeIFNone=(Write-Output $secInfoArray|Select-String -Pattern "^SeRelabelPrivilege" ).ToString().Split("=")[1] -replace "\s",""
		Write-Host "[-] SeRelabelPrivilege value should be None" -ForegroundColor Red
	}
	# 确保“同步目录服务数据”值为空
	$seSyncAgentPrivilegeIFNone=(Write-Output $secInfoArray|Select-String -Pattern "^SeSyncAgentPrivilege" -Quiet)
	if(-not $seSyncAgentPrivilegeIFNone){
		$seSyncAgentPrivilegeIFNone="True"
	}else{
		$seSyncAgentPrivilegeIFNone=(Write-Output $secInfoArray|Select-String -Pattern "^SeSyncAgentPrivilege" ).ToString().Split("=")[1] -replace "\s",""
		Write-Host "[-] SeSyncAgentPrivilege value should be None" -ForegroundColor Red
	}
	$userright_check_res="{""seTrustedCredManAccessPrivilegeIFNone"":""$seTrustedCredManAccessPrivilegeIFNone"",""seTcbPrivilegeIFNone"":""$seTcbPrivilegeIFNone"",""seMachineAccountPrivilegeIFOnlySpecifiedUserOrArray"":""$seMachineAccountPrivilegeIFOnlySpecifiedUserOrArray"",""seCreateGlobalPrivilegeIFNone"":""$seCreateGlobalPrivilegeIFNone"",""seDenyBatchLogonRightIFContainGuests"":""$seDenyBatchLogonRightIFContainGuests"",""seDenyServiceLogonRightIFContainGuests"":""$seDenyServiceLogonRightIFContainGuests"",""seDenyInteractiveLogonRightIFContainGuests"":""$seDenyInteractiveLogonRightIFContainGuests"",""seRemoteShutdownPrivilegeIFOnlySpecifiedUserOrArray"":""$seRemoteShutdownPrivilegeIFOnlySpecifiedUserOrArray"",""seRelabelPrivilegeIFNone"":""$seRelabelPrivilegeIFNone"",""seSyncAgentPrivilegeIFNone"":""$seSyncAgentPrivilegeIFNone""}"
	#Write-Host $userright_check_res
	return $userright_check_res
}
function Get-SecureOptionCheckRes{
	Param(
		[System.Collections.ArrayList]$secInfoArray
	)
	$
}



Write-Host "=================================="
Write-Host "|       Windows baseline check   |"
Write-Host "|         Author:JC0o0l          |"
Write-Host "|         version:1.0            |"
Write-Host "|         Date:20200103          |"
Write-Host "|         Mail:jerryzvs@163.com  |"
Write-Host "|      Wechat:Chroblert_Jerrybird|"
Write-Host "=================================="
Get-BasicInfo
$secInfoArray=Get-SecInfo
$account_check_res=Get-AccountPolicyCheckRes $secInfoArray
#Write-Host $account_check_res
$audit_check_res=Get-AuditPolicyCheckRes $secInfoArray
#Write-Host $audit_check_res
$userright_check_res=Get-UserRightPolicyCheckRes $secInfoArray
#Write-Host $userright_check_res