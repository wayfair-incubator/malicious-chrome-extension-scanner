# Malicious Chrome Extension Scanner


## Code of Conduct
See [Contributor Covenant](CODE%20OF%20CONDUCT.md)


## Architecture
![Workflow Diagram](/images/Malicious%20Chrome%20Extension%20Scanner%20Workflow.png)
 
> We choose the Drive Route

**NOTE** Other ways to extract extensions, other than tenable, is present in [other ways to extract extension](/other_ways_to_extract_extensions)

## Description
To implement a allowlist policy for chrome extensions, it was necessary to get the chrome extensions used by the employees and go about evaluating the risk associated with the chrome extension. Hence, a combination of the extensions pulled from tenable and passing those extensions to **Crxcavator** (a Duo product that scans extensions) provided the starting step for analysis of the extensions.


## PreRequisites
To run the script, you would need to fill in the details in [config.ini](config.ini)

### Output: Drive Option 
As we used the **Drive** Option as Output:
1. A service account in GSuite needs to be created
2. A GCP Project with service account having the following roles:
    - https://www.googleapis.com/auth/drive.file 
    - https://www.googleapis.com/auth/drive.appdata 
    - https://www.googleapis.com/auth/drive.readonly
    - https://www.googleapis.com/auth/spreadsheets
3. Add the GSuite Service Account to the Team Drive so that it can create a Google Sheet for output
4. Activate the Drive API in the Google API Console
5. Activate the Sheet API in the Google API Console
More info abt setting up GSuite Auth in https://developers.google.com/identity/protocols/oauth2/service-account

**NOTE** GCP Service Account doesn't need domain wide delegation access 

### Setting up Tenable
1. The current script uses **tags** from Tenable and uses **Source** tag. If you haven't setup tags before in Tenable, see https://docs.tenable.com/tenableio/vulnerabilitymanagement/Content/Settings/Tags.htm
Once a new tag is setup, you would to wait from a few hours depending on the number of assets. 
2. You will also need to setup a scan that has Windows plugin `96533` & Mac plugin `133180` enabled and scans once at least every 7 days.

### Setting up Crxcavator
Create an account in https://crxcavator.io/ to generate a key you will need in config.ini


## Installing requirements
```shell script
pip install -r requirements.lock
```


## Output
The script will generate multiple sheets in GDrive under the mentioned team drive.
- _Risky_Chrome_Extensions_datetimestamp_
- _Paid_Chrome_Extensions_datetimestamp_
- _Chrome_Extensions_Removed_from_Store_datetimestamp_
- _Version_Unavailable_in_Crxcavator_datetimestamp_
- _Unscanned_in_Crxcavator_datetimestamp_  

**NOTE** The script was unable to fetch any results on the extensions mentioned in _Unscanned_in_Crxcavator_datetimestamp_.


## Options
##### Run ```python -B main.py --help``` to get a list of the options.
```buildoutcfg
Usage: main.py [OPTIONS]

Options:
  -d, --duration INTEGER  Duration in days, that you want to
                          pull the extensions from tenable
  --help                  Show this message and exit.
```


## Examples:  
1. To get all extensions since the last 7 days of tenable on workstations, use 
```shell script
python -B main.py -d 7
```

**NOTE** Assuming the workstations are scanned once in 7 days 


## Score Calculation
Score is calculated by taking the total of each section mentioned in https://crxcavator.io/docs#/risk_breakdown ignoring **External metadata** & **WebStore**. RetireJS is calculated in the total score even though its not mentioned in the column.


## Remove Extension
Some of the ways to remove extension can be via [GPO](https://www.tecklyfe.com/how-to-prevent-google-chrome-extensions-in-group-policy/), [powershell script](/ways_to_remove_extension/powershell.ps1), bash script, removing registry keys associated with chrome extensions etc.


## Credits
Malicious Chrome Extension Scanner is owned and maintained by [MAINTAINERS](MAINTAINERS.md)


## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md)


## License
Malicious Chrome Extension Scanner is licensed under MIT License
See [LICENSE.md](LICENSE.md) for details.


## Release of new version
See [RELEASING.md](RELEASING.md)


## Need to report a vulnerability
See [SECURITY.md](SECURITY.md)
