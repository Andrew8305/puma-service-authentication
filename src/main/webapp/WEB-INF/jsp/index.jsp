<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>

<jsp:include page="includes/header.jsp" />

<div class="container">
	<c:if test="${!empty tenants}">
		<div class="row">
			<div class="span8 offset2">
				<h1>Tenants</h1>
				<form:form method="post" role="form" commandName="tenant" class="form-horizontal" action="proc/wayf">
					<div class="control-group">
						<form:label cssClass="control-label" path="id">Choose tenant:</form:label>
						<div class="controls">
							<select name="tenantId" class="form-control">
								<c:forEach items="${tenants}" var="tenant">
									<option value="${tenant.id}">${tenant.name}</option>
								</c:forEach>
							</select>
						</div>
					</div>
					<div class="control-group">
						<div class="controls">
							<input type="submit" value="Submit" class="btn" />
						</div>
					</div>
				</form:form>
			</div>
		</div>
	</c:if>
	<c:if test="${empty tenants}">
		<p>Could not find any tenants to redirect to!</p>
	</c:if>
</div>

<jsp:include page="includes/footer.jsp" />
