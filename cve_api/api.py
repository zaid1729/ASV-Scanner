import json
import os
import ijson
from flask import Flask, request, jsonify


class CVEDataHandler:
    def __init__(self, file_path):
        self.file_path = file_path

    def extract_product_from_cpe(self, cpe_uri):
        parts = cpe_uri.split(":")
        product = parts[4] if len(parts) > 4 else None
        version = parts[5] if len(parts) > 5 and parts[5] not in ("*") else None
        return product, version

    def parse_version(self, version):
        if not version:
            return None
        try:
            return tuple(map(int, version.split(".")))
        except ValueError:
            print(f"Warning: Could not parse version '{version}'")
            return None

    def filter_vulnerabilities(self, product, version):
        results = []
        try:
            with open(self.file_path, "r", encoding="utf-8") as file:
                parser = ijson.items(file, "CVE_Items.item")

                input_version = self.parse_version(version)
                if not input_version:
                    print(f"Warning: Could not parse version '{version}'")
                    return []

                for cve in parser:
                    cve_id = cve.get("cve", {}).get("CVE_data_meta", {}).get("ID", "Unknown")
                    configurations = cve.get("configurations", {}).get("nodes", [])

                    for node in configurations:
                        for cpe_match in node.get("cpe_match", []):
                            cpe_uri = cpe_match.get("cpe23Uri", "")
                            actual_product, cpe_version = self.extract_product_from_cpe(cpe_uri)

                            if actual_product and (actual_product.lower() == product.lower() or (
                                    product.lower() == "nginx" and actual_product.lower() == "nginx_open_source")):
                                cpe_version = self.parse_version(cpe_version)
                                version_start_incl = self.parse_version(cpe_match.get("versionStartIncluding", None))
                                version_start_excl = self.parse_version(cpe_match.get("versionStartExcluding", None))
                                version_end_excl = self.parse_version(cpe_match.get("versionEndExcluding", None))
                                version_end_incl = self.parse_version(cpe_match.get("versionEndIncluding", None))

                                match = False
                                # Debugging prints commented out
                                # print(f"Checking CVE: {cve_id}")
                                # print(f"  Product: {actual_product}, Input Version: {input_version}, CPE Version: {cpe_version}")
                                # print(f"  StartIncl: {version_start_incl}, StartExcl: {version_start_excl}, EndExcl: {version_end_excl}, EndIncl: {version_end_incl}")

                                if cpe_version and cpe_version == input_version:
                                    match = True
                                elif version_start_incl and version_end_excl:
                                    if version_start_incl <= input_version < version_end_excl:
                                        match = True
                                elif version_start_incl and version_end_incl:
                                    if version_start_incl <= input_version <= version_end_incl:
                                        match = True
                                elif version_start_excl and version_end_excl:
                                    if version_start_excl < input_version < version_end_excl:
                                        match = True
                                elif version_start_excl and version_end_incl:
                                    if version_start_excl < input_version <= version_end_incl:
                                        match = True
                                elif version_start_incl:
                                    if version_start_incl <= input_version:
                                        match = True
                                elif version_start_excl:
                                    if version_start_excl < input_version:
                                        match = True
                                elif version_end_excl:
                                    if input_version < version_end_excl:
                                        match = True
                                elif version_end_incl:
                                    if input_version <= version_end_incl:
                                        match = True

                                if match:
                                    results.append(cve)
                                    print(f"✅ CVE Found: {cve_id}")

                    if len(results) > 100:
                        yield results
                        results = []
        except Exception as e:
            print(f"Error processing CVE: {e}")
        if results:
            yield results


app = Flask(__name__)

data_path = os.path.join(os.path.dirname(__file__), "..", "data", "cves.json")
data_handler = CVEDataHandler(data_path)


@app.route("/vulnerabilities/", methods=["GET"])
def get_vulnerabilities():
    product = request.args.get("product")
    version = request.args.get("version")
    if not product or not version:
        return jsonify({"error": "Missing product or version parameter"}), 400

    results = []
    for batch in data_handler.filter_vulnerabilities(product, version):
        results.extend(batch)

    return jsonify({"vulnerabilities": results})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)