cas;
%let adminGroup = SASAdministrators;

/* FILENAME WLIST FILESRVC FOLDERPATH='/UAM'  FILENAME='WHITELIST_CONTROL.csv'; */
FILENAME WLIST FILESRVC FOLDERPATH='/UAM'  FILENAME='WHITELIST_CONTROL_09MAY2022.csv';

proc import
	DATAFILE=WLIST
	OUT=column_row_level
	DBMS=csv REPLACE;
run;

data column_level;
set column_row_level;
where Sec_level ="C";
run;

/* Create macro variables for each whitelist record */
proc sql noprint;
	select count(column),
		caslib,
		table,
		column,
		userGroup
	into :cnt
		, :caslib1-
		, :table1-
		, :column1-
		, :userGroup1-
	from column_level;
quit;

/* Distinct Table-Column List */
proc sql noprint;
	create table column_level_distinct as
		select distinct caslib,
			table,
			column,
			count(*) as dcnt
		from column_level;
quit;

proc sql noprint;
	select count(column), 
		caslib,
		table,
		column
	into :d_cnt
		, :D_caslib1-
		, :D_table1-
		, :D_column1-
	from column_level_distinct;
quit;

/* Loop start - apply permission for each column */
%macro looper_DenyALL;
	%do i=1 %to &d_cnt;
		%put DENY ALL EXCEPT ADMIN | NEXT TO PROCESS:;
		%put caslib: &&caslib&i;
		%put table: &&table&i;
		%put column: &&column&i;

		proc cas;
			accessControl.updSomeAcsColumn /
				acs={  
				{caslib="&&D_caslib&i",
				table="&&D_table&i",
				column="&&D_column&i",
				identity="*",		
				identityType="Group",
				permType="Deny",		
				permission="ReadInfo"},
				{caslib="&&D_caslib&i",
				table="&&D_table&i",
				column="&&D_column&i",
				identity="*",
				identityType="Group",
				permType="Deny",
				permission="Select"},
				{caslib="&&D_caslib&i",
				table="&&D_table&i",
				column="&&D_column&i",
				identity="&adminGroup",
				identityType="Group",
				permType="Grant",
				permission="ReadInfo"},
				{caslib="&&D_caslib&i",
				table="&&D_table&i",
				column="&&D_column&i",
				identity="&adminGroup",
				identityType="Group",
				permType="Grant",
				permission="Select"}
				};
		run;

		quit;

	%end;
%mend;

%macro looper_GrantWhitelist;
	%do i=1 %to &cnt;
		%put GRANT WHITELIST | NEXT TO PROCESS:;
		%put caslib: &&caslib&i;
		%put table: &&table&i;
		%put column: &&column&i;
		%put user group: &&userGroup&i;

		proc cas;
			accessControl.updSomeAcsColumn /
				acs={  
				{caslib="&&caslib&i",
				table="&&table&i",
				column="&&column&i",
				identity="&&userGroup&i",
				identityType="Group",
				permType="Grant",
				permission="ReadInfo"},
				{caslib="&&caslib&i",
				table="&&table&i",
				column="&&column&i",
				identity="&&userGroup&i",
				identityType="Group",
				permType="Grant",
				permission="Select"}
				};
		run;

		quit;

	%end;
%mend;

%macro apply_rls;

	data row_level;
		set column_row_level;
		where Sec_level ="R";
	run;

	Proc sql noprint;
		select count(*) into :st 
			from row_level;
	quit;

	%if &st > 0 %then
		%do;

			proc contents data=row_level(where=(row1 ne " ")) out=rlsd(where=(NAME contains 
				"row") keep=name) noprint;
			quit;

			proc sql noprint;
				select count(name),name
					into : rlsc , :rlnm separated by "," from rlsd;
				drop table rlsd;
			quit;

			data row_level;
				set row_level;

				%do i=1 %to &rlsc;
					if row&i ne "" then
						row_&i=catq('1A',row&i);
					drop row&i;
					rename row_&i=row&i;
				%end;
			run;

			data row_level;
				attrib grprls length=$32767.;
				set row_level;
				grprls=cat("substr","(",column,",","1",",","1",")"," ","in"," ","(",catx(",", &rlnm),")");
			run;

			proc sql noprint;
				select count(*),caslib ,table,userGroup,grprls 
					into :cn, :csln1-, :tb1- ,:uGp1-,:rls1-
						from row_level;
			quit;

			%do i=1 %to &cn;

				proc cas;
					accessControl.updSomeAcsTable /
						acs={
						{caslib="&&csln&i",
						table="&&tb&i",
						identity="&&uGp&i",
						identityType="Group",
						permType="Grant",
						permission="Select",
						filter="&&rls&i"},
						{caslib="&&csln&i",
						table="&&tb&i",
						identity="&&uGp&i",
						identityType="Group",
						permType="Grant",
						permission="ReadInfo"}};
				run;

			%end;
		%end;
%mend;

%looper_DenyALL;
%looper_GrantWhitelist;
%apply_rls;