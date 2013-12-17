<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>

<jsp:include page="includes/header.jsp" />

<div class="container">
	<c:if test="${!empty tenants}">
		<form:form method="post" role="form" commandName="tenant"
			class="form-wayf" action="proc/wayf">
			<h2 class="form-wayf-heading">Choose tenant</h2>
			<div class="form-group">
			<select name="tenantId" class="form-control">
				<c:forEach items="${tenants}" var="tenant">
					<option value="${tenant.id}">${tenant.name}</option>
				</c:forEach>
			</select>
			</div>
			<input type="submit" value="Submit" class="btn btn-primary btn-lg btn-block" />
		</form:form>
	</c:if>
	<c:if test="${empty tenants}">
		<p>Could not find any tenants to redirect to!</p>
	</c:if>
</div>

<jsp:include page="includes/footer.jsp" />
