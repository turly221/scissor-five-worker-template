import requests
from subprocess import Popen, PIPE
import os
import json
from operator import itemgetter
import time
import string

def write_properties(repo_path,repo_name):
    content = '''# must be unique in a given SonarQube instance
sonar.projectKey=%s

# --- optional properties ---
# defaults to project key
sonar.projectName=%s
# defaults to 'not provided'
sonar.projectVersion=1.0
 
# Path is relative to the sonar-project.properties file. Defaults to .
#sonar.sources=.
 
# Encoding of the source code. Default is default system encoding
sonar.sourceEncoding=UTF-8'''%(repo_name,repo_name)

    with open(os.path.join(repo_path,'sonar-project.properties'), 'w') as f:
        f.write(content)

def write_jsonFile(repo_name,sonar_results):
    with open(os.path.join(".", repo_name+".json"), 'w', encoding='utf-8') as f:
        json.dump(sonar_results, f, indent=4, ensure_ascii=False)

def execute_command(command,cwd):
    try:
        p = Popen(command,stdout=PIPE,cwd=cwd,shell=True)
        content = p.communicate()[0]
        out = content.decode("utf8","ignore")
        return out
    except Exception as e:
        raise print(command)

def generate_newToken(login, password, url, port):
    token = ''
    while 1:
        token_name = str(hash(time.time()))
        data = {
            'login': login,
            'name': token_name
        }
        link = url+':'+port+'/api/user_tokens/generate'
        response = requests.post(link, data=data, auth=(login, password))
        status = response.status_code
        # print(status)
        if status == 200:
            token = response.json()['token']
            # print(token)
            break
    return token

def sonar_scan(sonarScanner_path, url, port, repo_path, repo_name, token):
    command = sonarScanner_path + ' -Dsonar.projectKey='+repo_name + ' -Dsonar.sources=. '+ ' -Dsonar.host.url='+url+':'+port+ ' -Dsonar.login='+token
    # print(command)
    execute_command(command,repo_path)


def get_issues(login, password, url, port, repo_name, type):
    params = (
        ('componentKeys', repo_name),
        ('types', type),
    )
    link = url+':'+port+'/api/issues/search'
    response = requests.get(link, params=params, auth=(login, password))
    response_json = response.json()
    return response_json

def deal_vuln(vulnes):
    vuln_list = []
    key_list = ['rule','severity','component','textRange','message','tags','code_snippet']
    for v in vulnes['issues']:
        tmp = {}
        for key in key_list:
            if key in v.keys():
                tmp[key]=v[key]
            else:
                tmp[key]=[]
        vuln_list.append(tmp)
    return vuln_list

def get_result(login, password, url, port, repo_path, repo_name):
    vulnes_result = get_issues(login, password, url, port, repo_name,'VULNERABILITY') #BUG,VULNERABILITY
    vulnes = deal_vuln(vulnes_result)
    repo_info = {"repo_name": repo_name, "url": repo_path}
    sonar_results = {'repo_info': repo_info,'Vulnes':vulnes}
    print(">>> finish acquiring result.")
    #write_jsonFile(repo_name,sonar_results)
    return sonar_results

def sonar_result(sonarScanner_path, url, port, repo_path, repo_name):
    login = 'admin'
    password = 'admin123'
    write_properties(repo_path,repo_name)
    print(">>> finish writing properties.")
    token = generate_newToken(login, password, url, port)
    print(">>> finish generating token.")
    sonar_scan(sonarScanner_path, url, port, repo_path, repo_name, token)
    print(">>> finish sonarqube scanning.")
    return get_result(login, password, url, port, repo_path, repo_name)

def njs_result(repo_path, repo_name):
    save_path = './' + repo_name + 'njs.json'
    command = 'nodejsscan ' + repo_path + ' --json --sonarqube -o ' + save_path
    print(command)
    execute_command(command, os.getcwd())
    print('save_path', save_path)
    print(">>> finish nodejsscan scanning.")
    with open(save_path) as f:
        njs_re = json.load(f)
        print('njs_re', njs_re)
    return change_njs_form(njs_re)


def change_njs_form(njs_re):
    new_form_re = []
    for re in njs_re['issues']:
        pm_loc = re['primaryLocation']
        pm_loc_t = pm_loc['textRange']
        textRange = {'startLine' : pm_loc_t['startLine'] , 'endLine' : pm_loc_t['endLine'], 'startOffset' : pm_loc_t['startColumn'], 'endOffset' : pm_loc_t['endColumn']}
        n_re = {'rule' : re['ruleId'], 'severity' : re['severity'], 'component' : pm_loc['filePath'], 'textRange' : textRange, 'message' : pm_loc['message'], 'tags' : [], 'code_snp' : []}
        new_form_re.append(n_re)
    return new_form_re

def get_codesnp(repo_path, file, trange):
    with open(file, 'r') as f:
        lines = f.readlines()
        print('file name', file, 'length', len(lines))
        code_snp = ''
        for i in range(trange['startLine'], trange['endLine'] + 1):
            if i == trange['startLine'] and i == trange['endLine']:
                code_snp = lines[i - 1][trange['startOffset'] - 1 : trange['endOffset']]
            elif i == trange['startLine']:
                code_snp += lines[i-1][trange['startOffset'] - 1 :] + '\n'
            elif i == trange['endLine']:
                code_snp += lines[i-1][:trange['endOffset']]
            else:
                code_snp += lines[i-1] + '\n'
    return code_snp


def call_sast(sonarScanner_path, url, port, repo_path, repo_name):
    #sonar_re = sonar_result(sonarScanner_path, url, port, repo_path, repo_name)
    njs_re = njs_result(repo_path, repo_name)
    #merge_re = sonar_re
    #merge_re['Vulnes'] += njs_re
    for re in njs_re:
        re['code_snp'] = get_codesnp(repo_path, re['component'], re['textRange'])

    write_jsonFile(repo_name + '_only_test',njs_re)

if __name__ == "__main__":
    # sonarScanner_path = "/root/sonarqube/sonar-scanner-4.6.2.2472-linux/bin/sonar-scanner"
    sonarScanner_path = "sonar-scanner"
    url = "http://sonarqube"
    port = "9000"
    repo_path = "/root/SmartWeb"
    repo_name = "SmartWeb"
    call_sast(sonarScanner_path, url, port, repo_path, repo_name)
