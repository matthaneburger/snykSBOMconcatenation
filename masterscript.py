#!/usr/bin/env python3
import requests
import json
import os
from dotenv import load_dotenv
from colorama import Fore, Back, Style
from datetime import datetime

load_dotenv()

#GLOBALS
BASE_URL='https://api.snyk.io/rest'
API_TOKEN_ENV=os.getenv("MATTS_ADMIN_API_TOKEN")
GROUP_ID=os.getenv("HANEBURGER_MTN_GROUP_ID")
API_VERSION='2023-05-29'

ORG_ID=''
SBOM_FORMAT='cyclonedx1.4%2Bjson'

headers = {
    "Authorization": f'token {API_TOKEN_ENV}',
    "Content-Type": "application/json"
}

supported_sbom_formats=['deb', 'npm', 'pip', 'pipenv','dockerfile','rpm']
unsupported_sbom_formats=['sast']

def getAllProjectIdsInOrg(ORG_ID):
    ORG_ENDPOINT=f'{BASE_URL}/orgs/{ORG_ID}/projects?version={API_VERSION}'
    getAllProjects_response=requests.get(ORG_ENDPOINT, headers=headers)
    allProjects_data=getAllProjects_response.json()

    project_ids = []
    for project in allProjects_data['data']:
        project_ids.append(project['id'])
    return project_ids

def generateSBOMforOneProjectId(projectId):
    ORG_ENDPOINT=f'{BASE_URL}/orgs/{ORG_ID}/projects/{projectId}/sbom?version={API_VERSION}&format={SBOM_FORMAT}'
    sbomData_response=requests.get(ORG_ENDPOINT, headers=headers)
    sbom_data=sbomData_response.json()
    with open("test1.json", "w") as file:
        json.dump(sbom_data, file)

def getNameOfProject(projectId):
    ORG_ENDPOINT=f'{BASE_URL}/orgs/{ORG_ID}/projects/{projectId}?version={API_VERSION}'
    projectData_response=requests.get(ORG_ENDPOINT, headers=headers)
    project_data=projectData_response.json()
    projectName = project_data['data']['attributes']['name']
    return projectName

def getTypeOfProject(projectId):
    ORG_ENDPOINT=f'{BASE_URL}/orgs/{ORG_ID}/projects/{projectId}?version={API_VERSION}'
    projectType_response=requests.get(ORG_ENDPOINT, headers=headers)
    projectType_data=projectType_response.json()
    projectType = projectType_data['data']['attributes']['type']
    return projectType

def getNamesOfProjectsArray(projectsIdsArray):
    for projectId in projectsIdsArray:
        ORG_ENDPOINT=f'{BASE_URL}/orgs/{ORG_ID}/projects/{projectId}?version={API_VERSION}'
        projectData_response=requests.get(ORG_ENDPOINT, headers=headers)
        project_data=projectData_response.json()
        projectName = project_data['data']['attributes']['name']
        projectType = project_data['data']['attributes']['type']
        projectId = project_data['data']['id']
        if projectType in supported_sbom_formats:
            print(Fore.GREEN + projectName)
            print(Fore.GREEN + projectType)
            print(Fore.GREEN + projectId)
        else:
            print(Fore.RED + projectName)
            print(Fore.RED + projectType)
            print(Fore.RED + projectId)

def generateOneSBOM(projectId):
    sbomendpoint=f'{BASE_URL}/orgs/{ORG_ID}/projects/{projectId}/sbom?version={API_VERSION}&format={SBOM_FORMAT}'
    print(sbomendpoint)
    sbom_response=requests.get(sbomendpoint, headers=headers)
    sbom_data=sbom_response.json()
    projectFileType= getTypeOfProject(projectId)

    with open(f"{projectFileType}_SBOM.json", "w") as file:
        json.dump(sbom_data, file, indent=4)

def generateMultipleSBOMs(projectsIdsArray):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    directory=f"{SBOM_FORMAT}_{timestamp}"
    os.makedirs(directory, exist_ok=True)

    for projectId in projectsIdsArray:
        sbomendpoint=f'{BASE_URL}/orgs/{ORG_ID}/projects/{projectId}/sbom?version={API_VERSION}&format={SBOM_FORMAT}'
        sbom_response=requests.get(sbomendpoint, headers=headers)
        sbom_data=sbom_response.json()

        projectFileType= getTypeOfProject(projectId)

        with open(os.path.join(directory, f"{projectFileType}_{projectId}_SBOM.json"), "w") as file:
            json.dump(sbom_data, file, indent=4)
    print(Fore.CYAN + directory)
    return directory

def concatenateSbomsWithDirectory(directory_name):
    if not os.path.exists(directory_name):
        os.makedirs(directory_name)
    output_file=f"merged_SBOM.json"
    merged_data = {
        "$schema":"http://cyclonedx.org/schema/bom-1.4.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion":"1.4",
        "serialNumber":[],
        "version":1,
        "metadata":{},
        "components":[],
        "dependencies":[]
    }
    
    json_files = [file for file in os.listdir(directory_name) if file.endswith('.json')]

    for file in json_files:
        with open(os.path.join(directory_name, file), 'r') as f:
            data=json.load(f)

            #merged_data["serialNumber"].append(data["serialNumber"])

            merged_data["components"].extend(data.get("components", []))
            merged_data["dependencies"].extend(data.get("dependencies", []))
    with open(output_file,'w') as outfile:
        json.dump(merged_data, outfile, indent=4)

def main(): 
    projectsIdArray = getAllProjectIdsInOrg(ORG_ID)
    #print(projectsIdArray)
    for project in projectsIdArray:
        print(project)
    getNamesOfProjectsArray(projectsIdArray)
    concatenateSbomsWithDirectory(generateMultipleSBOMs(projectsIdArray))

if __name__=="__main__": 
    main() 