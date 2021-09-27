import json
import xmltodict

def reconstruct_criteria(criteria, tests, i):
    print(i, "INI I")

    if type(criteria) is dict:
        test = []

        if "criterion" in criteria:
            if type(criteria["criterion"]) == list:

                res = [
                    {
                        criteria["operator"]: []
                    }
                ]

                for criterion in criteria["criterion"]:
                    if criterion["test_ref"] in tests:
                        res[0][criteria["operator"]].append(tests[criterion["test_ref"]])
                
                return res

            else:
                if criteria["criterion"]["test_ref"] in tests:
                    for arr in tests[criteria["criterion"]["test_ref"]]:
                        test.append(arr)

        if test:
            return {
                criteria["operator"]: [
                    test,
                    reconstruct_criteria(criteria["criteria"], tests, i)
                ]
            }
        else:
            return {
                criteria["operator"]: [
                    reconstruct_criteria(criteria["criteria"], tests, i)
                ]
            }

    elif type(criteria) is list:
        print(type(criteria))

        res = []

        for data in criteria:

            test = []
            if "criteria" in data:
                res.append({
                    data["operator"]: [
                        reconstruct_criteria(data["criteria"], tests, i)
                    ]
                })
                continue

            if "criterion" in data:
                for criterion in data["criterion"]:
                    if i == 214: print(data)
                    if criterion["test_ref"] in tests:
                        test.append(tests[criterion["test_ref"]])

            res.append({
                data["operator"]: test
            })

        return res

            

with open("com.redhat.rhsa-all.xml") as xml_file:
    data_dict = xmltodict.parse(xml_file.read(), attr_prefix="")
    xml_file.close()

    json_data = json.dumps(data_dict, indent=4)
    dict_data = json.loads(json_data)

    states = {}
    objects = {}
    tests = {}


    """
    States
    """
    for state in dict_data["oval_definitions"]["states"]["red-def:rpminfo_state"]:
        states[state["id"]] = []

        if "red-def:arch" in state:
            data = [
                "arch",
                state["red-def:arch"]["operation"].replace(" ", "_"),
                state["red-def:arch"]["#text"]
            ]
            states[state["id"]].append(data)
        
        if "red-def:evr" in state:
            data = [
                "evr",
                state["red-def:evr"]["operation"].replace(" ", "_"),
                state["red-def:evr"]["#text"]
            ]
            states[state["id"]].append(data)

        if "red-def:signature_keyid" in state:
            data = [
                "signature_key_id",
                state["red-def:signature_keyid"]["operation"].replace(" ", "_"),
                state["red-def:signature_keyid"]["#text"]
            ]
            states[state["id"]].append(data)
        
    for state in dict_data["oval_definitions"]["states"]["unix-def:uname_state"]:
        states[state["id"]] = []

        if "unix-def:os_release" in state:
            data = [
                "os-release",
                state["unix-def:os_release"]["operation"].replace(" ", "_"),
                state["unix-def:os_release"]["#text"]
            ]
            states[state["id"]].append(data)

    for state in dict_data["oval_definitions"]["states"]["ind-def:textfilecontent54_state"]:
        states[state["id"]] = []

        if "ind-def:text" in state:
            data = [
                "text",
                state["ind-def:text"]["operation"].replace(" ", "_"),
                state["ind-def:text"]["#text"]
            ]
            states[state["id"]].append(data)

    for state in dict_data["oval_definitions"]["states"]["red-def:rpmverifyfile_state"]:
        states[state["id"]] = []

        if "red-def:name" in state:
            data = [
                "name",
                state["red-def:name"]["operation"].replace(" ", "_"),
                state["red-def:name"]["#text"]
            ]
            states[state["id"]].append(data)

        if "red-def:version" in state:
            data = [
                "version",
                state["red-def:version"]["operation"].replace(" ", "_"),
                state["red-def:version"]["#text"]
            ]
            states[state["id"]].append(data)
    
    """
    Objects
    """
    for object in dict_data["oval_definitions"]["objects"]["red-def:rpminfo_object"]:
        objects[object["id"]] = []

        if "red-def:name" in object:
            objects[object["id"]] = object["red-def:name"]
            
    """
    Tests
    """
    for test in dict_data["oval_definitions"]["tests"]["red-def:rpminfo_test"]:
        tests[test["id"]] = []

        object = ""
        if "red-def:object" in test:
            if test["red-def:object"]["object_ref"] in objects:
                object = objects[test["red-def:object"]["object_ref"]]

        if "red-def:state" in test:
            if test["red-def:state"]["state_ref"] in states:
                for state in states[test["red-def:state"]["state_ref"]]:
                    # if object:
                    #     print(object)
                    # #     state.insert(1, object)
                    tests[test["id"]].append(state)


    res = {
        "advisory": []
    }

    i = 0
    for definition in dict_data["oval_definitions"]["definitions"]["definition"]:
        if i == 4200: break
        cve = []
        cpe = []

        if "cve" in definition["metadata"]["advisory"]:
            if type(definition["metadata"]["advisory"]["cve"]) == dict:
                cve = [definition["metadata"]["advisory"]["cve"]["#text"]]
            else:
                cve = [cve["#text"] for cve in definition["metadata"]["advisory"]["cve"]]

        if "affected_cpe_list" in definition["metadata"]["advisory"]:
            if type(definition["metadata"]["advisory"]["affected_cpe_list"]) == dict:
                cpe = [definition["metadata"]["advisory"]["affected_cpe_list"]["cpe"]]
            else:
                cpe = [cpe for cpe in definition["metadata"]["advisory"]["affected_cpe_list"]["cpe"]]

        result = {
            "title": definition["metadata"]["title"],
            "fixes_cve": cve,
            "severity": definition["metadata"]["advisory"]["severity"],
            "affected_cpe": cpe
        }

        result["criteria"] = reconstruct_criteria(definition["criteria"], tests, i)
        res["advisory"].append(result)

        i += 1

    json_data = json.dumps(res, indent=4)

    with open("result.json", "w") as json_file:  
        json_file.write(json_data)
        json_file.close()
