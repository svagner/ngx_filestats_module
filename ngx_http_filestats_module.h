const char FILEHTML[] =
	"<!DOCTYPE HTML PUBLIC \\\"-//W3C//DTD HTML 4.01 Transitional//EN\\\">\n"
	"<html xmlns=\\\"http://www.w3.org/1999/xhtml\\\">\n"
	"	<head>\n"
	"		<style type=\"text/css\">\n"
	"			/*************\n"
	"			Blue Theme\n"
	"			*************/\n"
	"			/* overall */\n"
	"			.tablesorter-blue {\n"
	"				width: 100%%;\n"
	"				background-color: #fff;\n"
	"				margin: 10px 0 15px;\n"
	"				text-align: left;\n"
	"				border-spacing: 0;\n"
	"				border: #cdcdcd 1px solid;\n"
	"				border-width: 1px 0 0 1px;\n"
	"			}\n"
	"/*			.tablesorter-blue th,\n"
	"			.tablesorter-blue td {\n"
	"				border: #cdcdcd 1px solid;\n"
	"				border-width: 0 1px 1px 0;\n"
	"			}*/\n"
	"\n"
	"			/* header */\n"
	"/*			.tablesorter-blue th,\n"
	"			.tablesorter-blue thead td {\n"
	"				font: bold 12px/18px Arial, Sans-serif;\n"
	"				color: #000;\n"
	"				background-color: #99bfe6;\n"
	"				border-collapse: collapse;\n"
	"				padding: 4px;\n"
	"				text-shadow: 0 1px 0 rgba(204, 204, 204, 0.7);\n"
	"			}\n"
	"			.tablesorter-blue tbody td,\n"
	"			.tablesorter-blue tfoot th,\n"
	"			.tablesorter-blue tfoot td {\n"
	"				padding: 4px;\n"
	"				vertical-align: top;\n"
	"			}*/\n"
	"			.tablesorter-blue .header,\n"
	"			.tablesorter-blue .tablesorter-header {\n"
	"				background-image: url(data:image/gif;base64,R0lGODlhFQAJAIAAACMtMP///yH5BAEAAAEALAAAAAAVAAkAAAIXjI+AywnaYnhUMoqt3gZXPmVg94yJVQAAOw==);\n"
	"				background-repeat: no-repeat;\n"
	"				background-position: center right;\n"
	"				/*padding: 4px 18px 4px 4px;*/\n"
	"\n"
	"				font: bold 12px/18px Arial, Sans-serif;\n"
	"				color: #000;\n"
	"				white-space: normal;\n"
	"				cursor: pointer;\n"
	"			}\n"
	"			.tablesorter-blue .headerSortUp,\n"
	"			.tablesorter-blue .tablesorter-headerSortUp,\n"
	"			.tablesorter-blue .tablesorter-headerAsc {\n"
	"				background-color: #9fbfdf;\n"
	"				/* black asc arrow */\n"
	"				background-image: url(data:image/gif;base64,R0lGODlhFQAEAIAAACMtMP///yH5BAEAAAEALAAAAAAVAAQAAAINjI8Bya2wnINUMopZAQA7);\n"
	"				/* white asc arrow */\n"
	"				/* background-image: url(data:image/gif;base64,R0lGODlhFQAEAIAAAP///////yH5BAEAAAEALAAAAAAVAAQAAAINjI8Bya2wnINUMopZAQA7); */\n"
	"				/* image */\n"
	"				/* background-image: url(images/black-asc.gif); */\n"
	"			}\n"
	"			.tablesorter-blue .headerSortDown,\n"
	"			.tablesorter-blue .tablesorter-headerSortDown,\n"
	"			.tablesorter-blue .tablesorter-headerDesc {\n"
	"				background-color: #8cb3d9;\n"
	"				/* black desc arrow */\n"
	"				background-image: url(data:image/gif;base64,R0lGODlhFQAEAIAAACMtMP///yH5BAEAAAEALAAAAAAVAAQAAAINjB+gC+jP2ptn0WskLQA7);\n"
	"				/* white desc arrow */\n"
	"				/* background-image: url(data:image/gif;base64,R0lGODlhFQAEAIAAAP///////yH5BAEAAAEALAAAAAAVAAQAAAINjB+gC+jP2ptn0WskLQA7); */\n"
	"				/* image */\n"
	"				/* background-image: url(images/black-desc.gif); */\n"
	"			}\n"
	"			.tablesorter-blue thead .sorter-false {\n"
	"				background-image: none;\n"
	"				padding: 4px;\n"
	"			}\n"
	"\n"
	"			/* tfoot */\n"
	"			.tablesorter-blue tfoot .tablesorter-headerSortUp,\n"
	"			.tablesorter-blue tfoot .tablesorter-headerSortDown,\n"
	"			.tablesorter-blue tfoot .tablesorter-headerAsc,\n"
	"			.tablesorter-blue tfoot .tablesorter-headerDesc {\n"
	"				/* remove sort arrows from footer */\n"
	"				background-image: none;\n"
	"			}\n"
	"\n"
	"			/* tbody */\n"
	"			.tablesorter-blue td {\n"
	"				color: #3d3d3d;\n"
	"				background-color: #fff;\n"
	"				padding: 4px;\n"
	"				vertical-align: top;\n"
	"			}\n"
	"\n"
	"			/* hovered row colors\n"
	"			you'll need to add additional lines for\n"
	"			rows with more than 2 child rows\n"
	"			*/\n"
	"			.tablesorter-blue tbody > tr:hover > td,\n"
	"			.tablesorter-blue tbody > tr:hover + tr.tablesorter-childRow > td,\n"
	"			.tablesorter-blue tbody > tr:hover + tr.tablesorter-childRow + tr.tablesorter-childRow > td,\n"
	"			.tablesorter-blue tbody > tr.even:hover > td,\n"
	"			.tablesorter-blue tbody > tr.even:hover + tr.tablesorter-childRow > td,\n"
	"			.tablesorter-blue tbody > tr.even:hover + tr.tablesorter-childRow + tr.tablesorter-childRow > td {\n"
	"				background: #d9d9d9;\n"
	"			}\n"
	"			.tablesorter-blue tbody > tr.odd:hover > td,\n"
	"			.tablesorter-blue tbody > tr.odd:hover + tr.tablesorter-childRow > td,\n"
	"			.tablesorter-blue tbody > tr.odd:hover + tr.tablesorter-childRow + tr.tablesorter-childRow > td {\n"
	"				background: #bfbfbf;\n"
	"			}\n"
	"\n"
	"			/* table processing indicator */\n"
	"			.tablesorter-blue .tablesorter-processing {\n"
	"				background-position: center center !important;\n"
	"				background-repeat: no-repeat !important;\n"
	"				/* background-image: url(../addons/pager/icons/loading.gif) !important; */\n"
	"				background-image: url('data:image/gif;base64,R0lGODlhFAAUAKEAAO7u7lpaWgAAAAAAACH/C05FVFNDQVBFMi4wAwEAAAAh+QQBCgACACwAAAAAFAAUAAACQZRvoIDtu1wLQUAlqKTVxqwhXIiBnDg6Y4eyx4lKW5XK7wrLeK3vbq8J2W4T4e1nMhpWrZCTt3xKZ8kgsggdJmUFACH5BAEKAAIALAcAAAALAAcAAAIUVB6ii7jajgCAuUmtovxtXnmdUAAAIfkEAQoAAgAsDQACAAcACwAAAhRUIpmHy/3gUVQAQO9NetuugCFWAAAh+QQBCgACACwNAAcABwALAAACE5QVcZjKbVo6ck2AF95m5/6BSwEAIfkEAQoAAgAsBwANAAsABwAAAhOUH3kr6QaAcSrGWe1VQl+mMUIBACH5BAEKAAIALAIADQALAAcAAAIUlICmh7ncTAgqijkruDiv7n2YUAAAIfkEAQoAAgAsAAAHAAcACwAAAhQUIGmHyedehIoqFXLKfPOAaZdWAAAh+QQFCgACACwAAAIABwALAAACFJQFcJiXb15zLYRl7cla8OtlGGgUADs=') !important;\n"
	"			}\n"
	"\n"
	"			/* Zebra Widget - row alternating colors */\n"
	"			.tablesorter-blue tbody tr.odd td {\n"
	"				background-color: #ebf2fa;\n"
	"			}\n"
	"			.tablesorter-blue tbody tr.even td {\n"
	"				background-color: #fff;\n"
	"			}\n"
	"\n"
	"			/* Column Widget - column sort colors */\n"
	"			.tablesorter-blue td.primary,\n"
	"			.tablesorter-blue tr.odd td.primary {\n"
	"				background-color: #99b3e6;\n"
	"			}\n"
	"			.tablesorter-blue tr.even td.primary {\n"
	"				background-color: #c2d1f0;\n"
	"			}\n"
	"			.tablesorter-blue td.secondary,\n"
	"			.tablesorter-blue tr.odd td.secondary {\n"
	"				background-color: #c2d1f0;\n"
	"			}\n"
	"			.tablesorter-blue tr.even td.secondary {\n"
	"				background-color: #d6e0f5;\n"
	"			}\n"
	"			.tablesorter-blue td.tertiary,\n"
	"			.tablesorter-blue tr.odd td.tertiary {\n"
	"				background-color: #d6e0f5;\n"
	"			}\n"
	"			.tablesorter-blue tr.even td.tertiary {\n"
	"				background-color: #ebf0fa;\n"
	"			}\n"
	"\n"
	"			/* caption */\n"
	"			caption {\n"
	"				background: #fff;\n"
	"			}\n"
	"\n"
	"			/* filter widget */\n"
	"			.tablesorter-blue .tablesorter-filter-row td {\n"
	"				background: #eee;\n"
	"				line-height: normal;\n"
	"				text-align: center; /* center the input */\n"
	"				-webkit-transition: line-height 0.1s ease;\n"
	"				-moz-transition: line-height 0.1s ease;\n"
	"				-o-transition: line-height 0.1s ease;\n"
	"				transition: line-height 0.1s ease;\n"
	"			}\n"
	"			/* optional disabled input styling */\n"
	"			.tablesorter-blue .tablesorter-filter-row .disabled {\n"
	"				opacity: 0.5;\n"
	"				filter: alpha(opacity=50);\n"
	"				cursor: not-allowed;\n"
	"			}\n"
	"			/* hidden filter row */\n"
	"			.tablesorter-blue .tablesorter-filter-row.hideme td {\n"
	"				/*** *********************************************** ***/\n"
	"				/*** change this padding to modify the thickness     ***/\n"
	"				/*** of the closed filter row (height = padding x 2) ***/\n"
	"				padding: 2px;\n"
	"				/*** *********************************************** ***/\n"
	"				margin: 0;\n"
	"				line-height: 0;\n"
	"				cursor: pointer;\n"
	"			}\n"
	"			.tablesorter-blue .tablesorter-filter-row.hideme .tablesorter-filter {\n"
	"				height: 1px;\n"
	"				min-height: 0;\n"
	"				border: 0;\n"
	"				padding: 0;\n"
	"				margin: 0;\n"
	"				/* don't use visibility: hidden because it disables tabbing */\n"
	"				opacity: 0;\n"
	"				filter: alpha(opacity=0);\n"
	"			}\n"
	"			/* filters */\n"
	"			.tablesorter-blue .tablesorter-filter {\n"
	"				width: 98%%;\n"
	"				height: auto;\n"
	"				margin: 0;\n"
	"				padding: 4px;\n"
	"				background-color: #fff;\n"
	"				border: 1px solid #bbb;\n"
	"				color: #333;\n"
	"				-webkit-box-sizing: border-box;\n"
	"				-moz-box-sizing: border-box;\n"
	"				box-sizing: border-box;\n"
	"				-webkit-transition: height 0.1s ease;\n"
	"				-moz-transition: height 0.1s ease;\n"
	"				-o-transition: height 0.1s ease;\n"
	"				transition: height 0.1s ease;\n"
	"			}\n"
	"\n"
	"			/* ajax error row */\n"
	"/*			.tablesorter .tablesorter-errorRow td {\n"
	"				cursor: pointer;\n"
	"				background-color: #e6bf99;\n"
	"			}*/\n"
	"\n"
	"\n"
	"			.statsTable {\n"
	"				font-family:Arial, Helvetica, sans-serif;\n"
	"				color:#666;\n"
	"				font-size:12px;\n"
	"				text-shadow: 1px 1px 0px #fff;\n"
	"				background:#eaebec;\n"
	"				margin:20px;\n"
	"				border:#ccc 1px solid;\n"
	"				border-collapse:separate;\n"
	"\n"
	"				-moz-border-radius:3px;\n"
	"				-webkit-border-radius:3px;\n"
	"				border-radius:3px;\n"
	"\n"
	"				-moz-box-shadow: 0 1px 2px #d1d1d1;\n"
	"				-webkit-box-shadow: 0 1px 2px #d1d1d1;\n"
	"				box-shadow: 0 1px 2px #d1d1d1;\n"
	"				width: %s;\n"
	"				height: %s;\n"
	"			}\n"
	"\n"
	"			.statsTable th {\n"
	"				font-weight:bold;\n"
	"				padding:10px 15px 15px 10px;\n"
	"				border-top:1px solid #fafafa;\n"
	"				border-bottom:1px solid #e0e0e0;\n"
	"\n"
	"				background: #ededed;\n"
	"				background: -webkit-gradient(linear, left top, left bottom, from(#ededed), to(#ebebeb));\n"
	"				background: -moz-linear-gradient(top,  #ededed,  #ebebeb);\n"
	"			}\n"
	"			.statsTable li{\n"
	"				text-align: left;\n"
	"			}\n"
	"			.statsTable th:first-child{\n"
	"				/*text-align: left;*/\n"
	"				padding-left:2px;\n"
	"			}\n"
	"			.statsTable tr:first-child th:first-child{\n"
	"				-moz-border-radius-topleft:3px;\n"
	"				-webkit-border-top-left-radius:3px;\n"
	"				border-top-left-radius:3px;\n"
	"			}\n"
	"			.statsTable tr:first-child th:last-child{\n"
	"				-moz-border-radius-topright:3px;\n"
	"				-webkit-border-top-right-radius:3px;\n"
	"				border-top-right-radius:3px;\n"
	"			}\n"
	"			.statsTable tr{\n"
	"				text-align: center;\n"
	"				padding-left:20px;\n"
	"			}\n"
	"			.statsTable tr td:first-child{\n"
	"				text-align: left;\n"
	"				padding-left:20px;\n"
	"				border-left: 0;\n"
	"			}\n"
	"			.statsTable tr td {\n"
	"				padding:18px;\n"
	"				border-top: 1px solid #ffffff;\n"
	"				border-bottom:1px solid #e0e0e0;\n"
	"				border-left: 1px solid #e0e0e0;\n"
	"\n"
	"				background: #fafafa;\n"
	"				background: -webkit-gradient(linear, left top, left bottom, from(#fbfbfb), to(#fafafa));\n"
	"				background: -moz-linear-gradient(top,  #fbfbfb,  #fafafa);\n"
	"			}\n"
	"			.statsTable tr.even td{\n"
	"				background: #f6f6f6;\n"
	"				background: -webkit-gradient(linear, left top, left bottom, from(#f8f8f8), to(#f6f6f6));\n"
	"				background: -moz-linear-gradient(top,  #f8f8f8,  #f6f6f6);\n"
	"			}\n"
	"			.statsTable tr:last-child td{\n"
	"				border-bottom:0;\n"
	"			}\n"
	"			.statsTable tr:last-child td:first-child{\n"
	"				-moz-border-radius-bottomleft:3px;\n"
	"				-webkit-border-bottom-left-radius:3px;\n"
	"				border-bottom-left-radius:3px;\n"
	"			}\n"
	"			.statsTable tr:last-child td:last-child{\n"
	"				-moz-border-radius-bottomright:3px;\n"
	"				-webkit-border-bottom-right-radius:3px;\n"
	"				border-bottom-right-radius:3px;\n"
	"			}\n"
	"			.statsTable tr:hover td{\n"
	"				background: #f2f2f2;\n"
	"				background: -webkit-gradient(linear, left top, left bottom, from(#f2f2f2), to(#f0f0f0));\n"
	"				background: -moz-linear-gradient(top,  #f2f2f2,  #f0f0f0);    \n"
	"			}\n"
	"\n"
	"			.statsTable a:link {\n"
	"				color: #666;\n"
	"				font-weight: bold;\n"
	"				text-decoration:none;\n"
	"			}\n"
	"			.statsTable a:visited {\n"
	"				color: #999999;\n"
	"				font-weight:bold;\n"
	"				text-decoration:none;\n"
	"			}\n"
	"			.statsTable a:active,\n"
	"			.statsTable a:hover {\n"
	"				color: #bd5a35;\n"
	"				text-decoration:underline;\n"
	"			}\n"
	"		</style>\n"
	"		<script type=\"text/javascript\" src=\"http://ajax.googleapis.com/ajax/libs/jquery/1.4/jquery.min.js\"></script> \n"
	"		<script type=\"text/javascript\" src=\"http://mottie.github.io/tablesorter/js/jquery.tablesorter.js\"></script>\n"
	"		<script type=\"text/javascript\" src=\"http://mottie.github.io/tablesorter/js/jquery.tablesorter.widgets.js\"></script>\n"
	"		<script type=\"text/javascript\">\n"
	"			var REFRESH_INTERVAL = %d;\n"
	"			var TABLE_COLUMNS_COUNT = 6;\n"
	"\n"
	"			var updating = 0;\n"
	"\n"
	"			var originalTable = document.createElement(\"table\");\n"
	"\n"
	"			var req = createRequester();\n"
	"\n"
	"\n"
	"function createRequester()\n"
	"{\n"
	"	var result;\n"
	"\n"
	"	try\n"
	"	{\n"
	"		result = new ActiveXObject(\"Msxml2.XMLHTTP\");\n"
	"	}\n"
	"	catch (e)\n"
	"	{\n"
	"		try\n"
	"		{\n"
	"			result = new ActiveXObject(\"Microsoft.XMLHTTP\");\n"
	"		}\n"
	"		catch (e)\n"
	"		{\n"
	"			result = false;\n"
	"		}\n"
	"		result = false;\n"
	"	}\n"
	"\n"
	"	if (!result && typeof XMLHttpRequest != 'undefined')\n"
	"		result = new XMLHttpRequest();\n"
	"	return result;\n"
	"}\n"
	"\n"
	"function requestData(url)\n"
	"{\n"
	"	req.open(\"GET\", url, false);\n"
	"	req.send(null);\n"
	"	return req.responseText;\n"
	"}\n"
	"\n"
	"\n"
	"function buildTable(data)\n"
	"{\n"
	"	data = eval('(' + data + ')');\n"
	"\n"
	"	var headers = [ \"File size/Time\", %s ];\n"
	"\n"
	"	var table = document.createElement(\"table\");\n"
	"	var tableThead = document.createElement(\"thead\");\n"
	"\n"
	"	var updateHeader = document.createElement(\"li\");\n"
	"	updateHeader.id = \"updateStatus\";\n"
	"	updateHeader.className = \"statsTable\";\n"
	"	updateHeader.setAttribute(\"colspan\", headers.length);\n"
	"\n"
	"	table.appendChild(updateHeader);\n"
	"\n"
	"	var headerRow = document.createElement(\"tr\");\n"
	"	for (var h in headers)\n"
	"	{\n"
	"		var headerCell = document.createElement(\"th\");\n"
	"		headerCell.className += \"header\";\n"
	"		headerCell.innerHTML = headers[h];\n"
	"		headerRow.appendChild(headerCell);\n"
	"	}\n"
	"	tableThead.appendChild(headerRow);\n"
	"\n"
	"	table.appendChild(tableThead);\n"
	"\n"
	"	for (var us in data)\n"
	"	{\n"
	"		var usNameCell = document.createElement(\"th\");\n"
	"		usNameCell.textContent = us;\n"
	"\n"
	"		var firstUpsteamBackend = null;\n"
	"\n"
	"		// Times to size \n"
	"		for (var b in data[us])\n"
	"		{\n"
	"			if (b == data[us].length - 1)\n"
	"				break;\n"
	"\n"
	"			var backendRow = document.createElement(\"tr\");\n"
	"\n"
	"			// Backend parameters\n"
	"			for (var param in data[us][b])\n"
	"			{\n"
	"				var paramCell = document.createElement(\"td\");\n"
	"				paramCell.textContent = data[us][b][param];\n"
	"				backendRow.appendChild(paramCell);\n"
	"			}\n"
	"\n"
	"			if (b == 0) // first upstream row\n"
	"				backendRow.insertBefore(usNameCell, backendRow.firstChild);\n"
	"\n"
	"			table.appendChild(backendRow);\n"
	"		}\n"
	"	}\n"
	"\n"
	"	var content = document.getElementById(\"content\");\n"
	"	content.innerHTML = \"<table class='statsTable' id='mystatsTable'>\" + table.innerHTML + \"</table>\"; // WTF\n"
	"\n"
	"	originalTable.innerHTML = table.innerHTML;\n"
	"	if(typeof jQuery!=\"undefined\")\n"
	"	{\n"
	"	    $('#mystatsTable').tablesorter({\n"
	"	    theme: 'blue',\n"
	"	    widgets: [\"saveSort\", \"zebra\"]\n"
	"	    });\n"
	"	}\n"
	"}\n"
	"\n"
	"function onSortResetClick()\n"
	"{\n"
	"	$('table').trigger('saveSortReset').trigger(\"sortReset\");\n"
	"}\n"
	"\n"
	"function onResetClick()\n"
	"{\n"
	"	var temp = requestData(\"?reset\");\n"
	"       var data = requestData(\"?json\");\n"
	"       updateTable(data);\n"
	"}\n"
	"\n"
	"function updateTable(data)\n"
	"{\n"
	"	if (updating == 0)\n"
	"	{\n"
	"		updating = 1;\n"
	"\n"
	"		buildTable(data);\n"
	"		updating = 0;\n"
	"\n"
	"		// Update last update time\n"
	"		var statusHeader = document.getElementById(\"updateStatus\");\n"
	"		var now = new Date();\n"
	"		var Minutes = ((now.getMinutes() < 10) ? \":0\" : \":\") + now.getMinutes();\n"
	"		var Seconds = ((now.getSeconds() < 10) ? \":0\" : \":\") + now.getSeconds();\n"
	"		statusHeader.innerHTML = \"Last update: \" + now.getHours() + Minutes + Seconds + \"   <button onClick='onSortResetClick()'>Reset Sort</button>\" + \"   <button onClick='onResetClick()'>Reset stats</button>\";\n"
	"	}\n"
	"}\n"
	"\n"
	"function onTimer()\n"
	"{\n"
	"	var data = requestData(\"?json\");\n"
	"	updateTable(data);\n"
	"}\n"
	"\n"
	"window.onload = function()\n"
	"{\n"
	"	onTimer();\n"
	"	setInterval(onTimer, REFRESH_INTERVAL); // TODO request parameters from nginx\n"
	"}\n"
	"\n"
	"</script>\n"
	"	<title>FileStats Plugin - NGINX (127.0.0.1)</title>	\n"
	"</head>\n"
	"<body>\n"
	"<div id=\"headerCopying\" align=right><a href='http://bsdway.ru' style='font-size: 6px'>Vagner(c)</a></div>	\n"
	"<table width=\"100%%\" height=\"100%%\" id='statsTable'>\n"
	"<tr>\n"
	"<td align=\"right\" valign=\"middle\">\n"
	"<div id=\"content\"></div>\n"
	"</td>\n"
	"</tr>\n"
	"</table>\n"
	"</body>\n"
	"</html>\n";
