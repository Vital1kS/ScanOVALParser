import csv
import codecs
import sys
import os
from bs4 import BeautifulSoup


def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)
def split_multimple_vul(vuls):
    new_vuls = []
    for vul in vuls:
        if len(vul) == 10:
            new_vuls.append(vul)
        else:
            splited_vul = [vul[i:i + 10] for i in range(0, len(vul), 10)]
            new_vuls.append(splited_vul)
    print(new_vuls)
    return new_vuls
def generate_csv(report_name):
    report = codecs.open(report_name,"r","utf_8_sig")
    soup = BeautifulSoup(report, "html.parser")
    vuls = soup.find_all("td", {"class": "bdu"})
    for i in range(len(vuls)):
        vuls[i] = vuls[i].get_text().replace("BDU:","")
    vuls = split_multimple_vul(vuls)
    cve_dict = {}
    with codecs.open(resource_path("cwe.csv"),"r",'utf_8_sig') as cwe_cve:
        cve_reader = csv.reader(cwe_cve,delimiter=';',quotechar='|')
        for cve_elem in cve_reader:
            cve_dict[cve_elem[0].strip()[1:]] = cve_elem[2].split(",")
    cwe_dict = {}
    with codecs.open(resource_path("cwe.csv"),"r",'utf_8_sig') as cwe_cve:
        cwe_reader = csv.reader(cwe_cve,delimiter=';',quotechar='|')
        for cwe_elem in cwe_reader:
            cwe_dict[cwe_elem[0].strip()[1:]] = cwe_elem[1].split(",")
    capec_dict = {}
    with codecs.open(resource_path("capec.csv"),"r",'utf_8_sig') as capec:
        capec_reader = csv.reader(capec,delimiter=';',quotechar='|')
        for capec_elem in capec_reader:
            capec_dict[capec_elem[0].strip()[1:]] = capec_elem[1].split(",")
    level_dict = {}
    with codecs.open(resource_path("level.csv"),"r",'utf_8_sig') as level:
        level_reader = csv.reader(level,delimiter=';',quotechar='|')
        for level_elem in level_reader:
            level_dict[level_elem[0].strip()[1:]] = level_elem[1].split(",")
    with codecs.open('result.csv', 'w',encoding='utf_8_sig') as csvfile:
        csvwriter = csv.writer(csvfile, delimiter=';', quotechar='|')
        csvwriter.writerow(["№","Наименование уязвимости","CVE","CWE","Capec High","Capec Medium","Capec Low","No chance"])
        number = 0
        for vul in vuls:
            row = [""]*8
            if type(vul) == list:
                for element in vul:
                    row[1] += "BDU:"+element+", "
                row[1] = row[1][:-2]
                vul = vul[0]
            else:
                row[1]="BDU:"+vul
            cve_str=""
            for cve in cve_dict[vul]:
                cve_str+=cve+","
            cve_str = cve_str[:-1]
            row[2]="CVE-"+cve_str
            for cwe in cwe_dict[vul]:
                number+=1
                temp_row = row.copy()
                temp_row[0] = number
                if(cwe != '-'):
                    temp_row[3] = "CWE-"+cwe
                    for capec in capec_dict[cwe.strip()]:
                        if capec.strip() != '-':
                            if level_dict[capec.strip()][0] == "High":
                                temp_row[4] += capec+", "
                            elif level_dict[capec.strip()][0] == "Medium":
                                temp_row[5] += capec+", "
                            elif level_dict[capec.strip()][0] == "Low":
                                temp_row[6] += capec+", "
                            else:
                                temp_row[7] += capec+", "
                    temp_row[4] = temp_row[4][:-2]
                    temp_row[5] = temp_row[5][:-2]
                    temp_row[6] = temp_row[6][:-2]
                    temp_row[7] = temp_row[7][:-2]
                csvwriter.writerow(temp_row)
        csvfile.close()

for filename in os.listdir("."):
    if os.path.isfile(filename):
        if filename.endswith(".html"):
            generate_csv(filename)
