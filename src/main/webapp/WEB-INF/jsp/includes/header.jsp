<!DOCTYPE html>

<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>

<html>
<head>
<meta charset="utf-8">
<title><c:out value="${title}"/></title>

<meta content="IE=edge,chrome=1" http-equiv="X-UA-Compatible">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<!-- Bootstrap -->
<link href="<c:url value="/resources/css/bootstrap.css"/>"
	rel="stylesheet" media="screen" />
<link href="<c:url value="/resources/css/navbar-fixed-top.css"/>"
	rel="stylesheet" />

<!-- HTML5 shim and Respond.js IE8 support of HTML5 elements and media queries -->
<!--[if lt IE 9]>
      <script src="/resources/js/html5shiv.js"></script>
      <script src="/resources/js/respond.min.js"></script>
    <![endif]-->
</head>
<body>
<div class="navbar navbar-default navbar-fixed-top">
	<div class="container">
		<div class="navbar-header">
			<button type="button" class="navbar-toggle" data-toggle="collapse"
				data-target=".navbar-collapse">
				<span class="icon-bar"></span> <span class="icon-bar"></span> <span
					class="icon-bar"></span>
			</button>
			<a class="navbar-brand" href="#">PUMA</a>
		</div>
		<!--/.nav-collapse -->
	</div>
</div>

	
<div class="container">
	<c:forEach var="msg" items="${msgs}" varStatus="status">
		<c:choose>
			<c:when test="${msg.type == 'success'}">
				<c:set var="alertClass" value="alert-success" />
			</c:when>
			<c:when test="${msg.type == 'failure'}">
				<c:set var="alertClass" value="alert-danger" />
			</c:when>
			<c:otherwise>
				<c:set var="alertClass" value="alert-info" />
			</c:otherwise>
		</c:choose>
		<div class="alert <c:out value="${alertClass}" /> alert-dismissable">
			<button type="button" class="close" data-dismiss="alert"
				aria-hidden="true">&times;</button>
			<c:out value="${msg.message}" />
		</div>
	</c:forEach>
</div>