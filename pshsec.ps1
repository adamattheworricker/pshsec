#Get local users
Get-LocalUser

#Get local groups
Get-LocalGroup

#For each group, get members. error 1789 indicates lack of privs to read group members
Get-LocalGroup | Select-Object -ExpandProperty Name | Out-File .\LocalGroups.txt
Get-Content .\LocalGroups.txt | ForEach-Object{
    Write-Output $_
    Get-LocalGroupMember $_
}

#Get listening ports
Get-NetTCPConnection | Where-Object State -EQ Listen

#Get patches
Get-HotFix

#Find backup file (change for other interesting file types)
Get-ChildItem *.bak* -Recurse

#Find string within files (change for other interesting strings)
Get-ChildItem *.* -Recurse | Select-String 'API_KEY'

#Get Permissions on a drive
Get-ACL C:\

#Pipe to Gridview for nice GUI
Out-GridView

#This stuff needs Powerview.ps1

#Get domain users
Get-NetUser

#Get domain groups
Get-NetGroup

#Get domain admins/members of groups
Get-NetGroupMember | Where-Object Name -EQ 'Domain Admins'

#Get network computers
Get-NetComputers

#find domain shares
Find-DomainShare -CheckShareAccess

#find domain trusts
Get-NetDomainTrust

#find machines where you have local admin
Find-LocalAdminAccess
