#User Access Matrix – Column and Row Level Security for CAS Tables Documentation  
 
Product: Information Catalog   
Version: SAS Viya 4  
Date: 12/04/2023 

This code provides means to implement Row-level and Column-level securities within SAS Viya's CAS in an automated way. The code relies from a file (WHITELIST_CONTROL_UAM.csv), wherein the library, table, row, column and conditions are present.

Note that:
1. SAS Visual Analytics, column-level access is not supported and can yield unexpected results.
https://go.documentation.sas.com/doc/en/sasadmincdc/v_047/calauthzcas/n1bf0cwn6ae85gn1b64x2j0czu24.htm?fromDefault=#p0uelekjo1z7ean1u8r4bj8n06cq

2. Defect/Fix on : Compute fails to return rows from a CAS table with RLS
https://rndjira.sas.com/browse/COMPUTESVCS-54267
