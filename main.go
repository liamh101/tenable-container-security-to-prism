package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type TESBaseFile struct {
	Findings  []TCSFinding
	ImageName string `json:"image_name"`
}

type TCSFinding struct {
	NvdFinding struct {
		Title       string
		Description string
		Status      string
		CvssVector  string `json:"cvss_vector"`
		CvssScore   string `json:"cvss_score"`
		Cve         string
		Remediation string
		References  []string
	}
	Packages []struct {
		Name    string
		Version string
		Type    string
	}
}

type CveDetails struct {
	Title string
}

type PrismBaseFile struct {
	Version int         `json:"version"`
	Issues  []PrismItem `json:"issues"`
}

type PrismItem struct {
	Name                    string      `json:"name"`
	OriginalRiskRating      string      `json:"original_risk_rating"`
	ClientDefinedRiskRating string      `json:"client_defined_risk_rating"`
	Finding                 string      `json:"finding"`
	Recommendation          string      `json:"recommendation"`
	CvssVector              string      `json:"cvss_vector"`
	AffectedHosts           []PrismHost `json:"affected_hosts"`
	Cves                    []string    `json:"cves"`
	References              []string    `json:"references"`
	TechnicalDetails        string      `json:"technical_details"`
}

type PrismHost struct {
	Name string `json:"name"`
}

func main() {
	var filename = os.Args[1]
	fmt.Println("Looking for Tenable File: " + filename)

	inspectorResult := parseTenableFile(filename)
	prismResult := tenableToPrism(inspectorResult)

	data, _ := json.Marshal(prismResult)

	var finalFilename = strings.Split(filename, ".")[0]

	fmt.Println("Creating File: " + finalFilename + "_prism.json")
	f, _ := os.Create(finalFilename + "_prism.json")
	f.WriteString(string(data))
	f.Sync()
}

func parseTenableFile(filename string) TESBaseFile {
	jsonFile, err := os.Open(filename)

	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("File found")
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	var result TESBaseFile
	json.Unmarshal([]byte(byteValue), &result)

	return result
}

func tenableToPrism(baseFile TESBaseFile) PrismBaseFile {
	var prismFile PrismBaseFile
	var prismHost PrismHost

	prismHost.Name = baseFile.ImageName

	prismFile.Version = 1

	for _, finding := range baseFile.Findings {
		var prismItem PrismItem
		prismItem.Name = finding.NvdFinding.Cve
		prismItem.Finding = finding.NvdFinding.Description
		prismItem.Recommendation = finding.NvdFinding.Remediation
		prismItem.ClientDefinedRiskRating = cvssToPrism(finding.NvdFinding.CvssScore)
		prismItem.OriginalRiskRating = cvssToPrism(finding.NvdFinding.CvssScore)
		prismItem.CvssVector = finding.NvdFinding.CvssVector
		prismItem.TechnicalDetails = parseTechnicalDetails(finding)

		prismItem.Cves = append(prismItem.Cves, finding.NvdFinding.Cve)
		prismItem.References = finding.NvdFinding.References

		prismItem.AffectedHosts = append(prismItem.AffectedHosts, prismHost)
		prismFile.Issues = append(prismFile.Issues, prismItem)
	}

	return prismFile
}

func parseTechnicalDetails(finding TCSFinding) string {
	if len(finding.Packages) == 0 {
		return ""
	}

	var techDetails = "<h3>Affected Packages</h3>"
	techDetails = "<table><thead><tr><th>Name</th><th>Version</th><th>Type</th></tr></thead><tbody>"

	for _, packageItem := range finding.Packages {
		techDetails += "<tr><td>" + packageItem.Name + "</td>" + "<td>" + packageItem.Version + "</td><td>" + packageItem.Type + "</td>"
	}

	techDetails += "</tbody></table>"

	return techDetails
}

func getName(cve string) string {
	//https://cve.circl.lu/api/cve/
	var client = &http.Client{}

	fmt.Println("Finding Title for: " + cve)

	res, err := client.Get("https://cve.circl.lu/api/cve/" + cve)

	if err != nil {
		log.Fatal(err)
	}

	body, err := io.ReadAll(res.Body)
	res.Body.Close()

	if err != nil {
		log.Fatal(err)
	}

	var result CveDetails

	json.Unmarshal(body, &result)

	fmt.Println("Cve Title: " + result.Title)

	return result.Title
}

func cvssToPrism(rating string) string {
	var ratingFloat = 0.0

	ratingFloat, err := strconv.ParseFloat(rating, 64)

	if err != nil {
		fmt.Println(ratingFloat)
		return "Info"
	}

	if ratingFloat == 0.0 {
		return "Info"
	}

	if ratingFloat > 0.1 && ratingFloat < 3.9 {
		return "Low"
	}

	if ratingFloat > 4.0 && ratingFloat < 6.9 {
		return "Medium"
	}

	if ratingFloat > 7.0 && ratingFloat < 8.9 {
		return "High"
	}

	return "Critical"
}
