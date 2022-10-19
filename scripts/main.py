import json
import zipfile
import os

"""
以class_name为key，以影响到的line为value
"""


def class_to_lines():
    with open("../cflow_result_wlq.json", "r") as f:
        data = json.load(f)
        result = {}
        for _k, vs in data.items():
            for v in vs:
                className = v["className"]
                if className not in result.keys():
                    result[className] = []
                lineNumber = v["lineNumber"]
                result[className].append(lineNumber)
        with open("../class_to_lines.json", "w") as f2:
            json.dump(result, f2)


"""
检查哪些java类没有被影响
"""


def get_not_affected_class():
    PATH_HADOOP_COMMON = "../app/hadoop-2.8.5/share/hadoop/common"
    JARS = ["hadoop-nfs-2.8.5.jar", "hadoop-common-2.8.5.jar"]
    PATH_JARS = []
    for jar in JARS:
        PATH_JARS.append(os.path.join(PATH_HADOOP_COMMON, jar))
    print(PATH_JARS)

    with open("../class_to_lines.json", "r") as f:
        data = json.load(f)
        affected_class = list(data.keys())
        all_class = []
        for jar in PATH_JARS:
            with zipfile.ZipFile(jar) as z:
                for c in z.namelist():
                    if ".class" not in c:
                        continue
                    c = c.split(".")[0]
                    c = c.replace("/", ".")
                    all_class.append(c)
        print(len(affected_class))
        print(len(all_class))
        not_affected_class = list(set(all_class) - set(affected_class))
        print(len(not_affected_class))
        result = {
            "affected_class": affected_class,
            "not_affected_class": not_affected_class
        }
        with open("../not_affected_class.json", "w") as f2:
            json.dump(result, f2)


class_to_lines()
get_not_affected_class()
