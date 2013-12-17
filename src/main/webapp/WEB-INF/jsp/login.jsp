<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>

<jsp:include page="includes/header.jsp" />

<div class="container">

	<form:form method="post" class="form-signin" action="proc/login"
		role="form">
		<h2 class="form-signin-heading">Please log in</h2>
		<input type="text" class="form-control" placeholder="Login name"
			name="loginName" id="loginName" required autofocus>
		<input type="password" class="form-control" placeholder="Password"
			name="password" id="password" required>
		<button class="btn btn-lg btn-primary btn-block" type="submit">Log
			in</button>
	</form:form>

</div>

<jsp:include page="includes/footer.jsp" />
