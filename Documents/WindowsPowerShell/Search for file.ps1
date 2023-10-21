$filename = '*.jpg'
$searchinfolder = 'c:\users\jerri\fonts'
Get-ChildItem -Path $searchinfolder -Filter $filename -Recurse | %{$_.FullName}