# KQL-updates
KUSTO Query Language - Update and event searching


Update
let lastDayComputersMissingUpdates = Update
| where TimeGenerated between (ago(3d)..ago(2d))
| where Classification == 'Critical Updates' and UpdateState != 'Not needed' and UpdateState != 'NotNeeded'
| summarize makeset(Computer);

Update
| where TimeGenerated > ago(1d)
| where Classification == 'Critical Updates' and UpdateState != 'Not needed' and UpdateState != 'NotNeeded'
| where Computer in (lastDayComputersMissingUpdates)
| summarize UniqueUpdatesCount = dcount(Product) by Computer, OSType
 
Update
| where OSType != “Linux” and UpdateState == “Needed” and Optional == “false” and (Classification == “Security Updates” or Classification == “Critical Updates”)
| summarize UniqueUpdatesCount = count(), makeset(Title), makeset(KBID) by Computer
 
Update
| where TimeGenerated >= ago(7d)
| where UpdateState == “Needed”
| summarize UpdatesNeeded=makeset(Title), Updates=dcount(Title) by Computer
| join kind= innerunique
(
SecurityDetection
| where TimeGenerated >= ago(7d)
| where AlertSeverity == “High”
| summarize SecurityAlerts=makeset(AlertTitle), HighAlertsCount=count() by Computer
)
on Computer
| project-away Computer
 

Event Log

let detections = toscalar(SecurityDetection
| summarize makeset(Computer));
SecurityEvent
| where Computer in (detections) and EventID == 4624
| summarize count() by Account
 
SecurityEvent
| where EventID in (4624, 4634)
| project Computer, Account, TargetLogonId, TimeGenerated, EventID
| order by TimeGenerated asc, EventID asc
| summarize TimeList = makelist(TimeGenerated/1s, 100000) by Computer, Account, TargetLogonId
| extend SessionDuration = series_fir(TimeList, dynamic([1,-1]), false, false)
| mvexpand SessionDuration limit 1000000
| extend SessionDuration = todouble(SessionDuration)
| where SessionDuration != todouble(TimeList[0])
| project-away TimeList
| summarize count(), SessionDuration=avg(SessionDuration), dcount(TargetLogonId), dcount(Account) by Computer
| order by SessionDuration asc
 
SecurityEvent
| project Activity
| parse Activity with activityID ” – “ activityDesc
| take 100
 

SecurityEvent
| project Activity
| extend activityArr=split(Activity, ” – “)
| project Activity , activityArr, activityId=activityArr[0]
| take 100
 
SecurityEvent
| project Activity
| parse Activity with activityID ” – “ activityDesc
| summarize count() by activityID
 

