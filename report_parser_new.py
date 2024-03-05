import pandas as pd
import codecs
import csv
from selenium import webdriver
from bs4 import BeautifulSoup

driver = webdriver.Chrome()
cwe_base_url = "https://cwe.mitre.org/data/definitions/"
capec_base_url = "https://capec.mitre.org/data/definitions/"

def import_data():
    input_file="vullist.xlsx"
    with codecs.open(input_file,"r","utf_8_sig") as import_data:
        reader = pd.read_excel(input_file)
        output_file = "cwe.csv"
        reader = reader.reset_index()
        for index, row in reader.iterrows():
            temp_dict = []
            if "BDU:" in row[1]:
                bdu = row[1].replace("BDU:","")
                temp_dict.append(bdu)
                if type(row[23]) == str:
                    temp_dict.append(row[23].replace("CWE-",""))
                else:
                    temp_dict.append("-")
                if type(row[19]) == str:
                    cve = row[19].split(',')
                    cve2=""
                    for i in range(len(cve)):
                        if "CVE-" in cve[i]:
                            cve2+=cve[i].replace("CVE-","")+", "
                    if cve2 == "":
                        temp_dict.append("-")
                    temp_dict.append(cve2[:-2])
                else:
                    temp_dict.append("-")
                with codecs.open(output_file, "a","utf_8_sig") as export_data:
                    csv.writer(export_data,delimiter=';',quotechar='|').writerow(temp_dict)
def get_capec():
    with codecs.open("cwe.csv", "r","utf_8_sig") as readfile: 
        reader = csv.reader(readfile,delimiter=';',quotechar='|')
        cwe_list = []
        for row in reader:
            cwes = row[1].split(',')
            for cwe in cwes:
                if cwe != '-':
                    cwe_list.append(cwe)
        cwe_list = set(cwe_list)
        for cwe in cwe_list:
            print(cwe)
            capec_list=[]
            capec_str=""
            cwe = cwe.strip()
            capec_list.append(cwe)
            driver.get(cwe_base_url+cwe+".html")
            html_page = driver.page_source
            soup = BeautifulSoup(html_page, 'html.parser')
            capecs = soup.find("div",{"id":"Related_Attack_Patterns"})
            if capecs != None:
                capecs = capecs.find_all("a")
                for capec in capecs[1:]:
                    capec_str += (capec.get_text().replace("CAPEC-",""))+", "
                capec_list.append(capec_str[:-2])
            else:
                capec_list.append("-")
            with codecs.open("capec.csv", "a","utf_8_sig") as outfile: 
                csv.writer(outfile,delimiter=';',quotechar='|').writerow(capec_list)
def get_level():
    capec_list = []
    with codecs.open("capec.csv", "r","utf_8_sig") as readfile: 
        reader = csv.reader(readfile,delimiter=';',quotechar='|')
        for row in reader:
            if row[1] != '-':
                temp_capecs = row[1].split(",")
                for temp_capec in temp_capecs:
                    capec_list.append(temp_capec)
    capec_list = set(capec_list)
    for capec in capec_list:
        capec = capec.strip()
        print(capec)
        driver.get(capec_base_url+capec+".html")
        html_page = driver.page_source
        soup = BeautifulSoup(html_page, 'html.parser')
        level = soup.find("div",{"id":"Likelihood_Of_Attack"})
        level_list=[]
        level_list.append(capec)
        if level != None:
            level = level.find("p").get_text()
            level_list.append(level)
        else:
            level_list.append("No")
        with codecs.open("level.csv", "a","utf_8_sig") as outfile: 
            csv.writer(outfile,delimiter=';',quotechar='|').writerow(level_list)
import_data()