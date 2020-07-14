SELECT * FROM chrome_extensions WHERE chrome_extensions.uid IN (SELECT uid FROM users)
