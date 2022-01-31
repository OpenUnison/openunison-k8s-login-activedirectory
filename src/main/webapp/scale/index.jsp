<!--
Copyright 2015 Tremolo Security, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 -->
<html ng-app="scale" lang="en">
<head >
	    <meta charset="utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
		<meta http-equiv="cache-control" content="max-age=0" />
		<meta http-equiv="cache-control" content="no-cache" />
		<meta http-equiv="expires" content="0" />
		<meta http-equiv="expires" content="Tue, 01 Jan 1980 1:00:00 GMT" />
		<meta http-equiv="pragma" content="no-cache" />
    <title>Tremolo Security Scale</title>

    <!-- Bootstrap -->
    <link href="css/bootstrap.min.css" rel="stylesheet" />
		<link href="css/angular.treeview.css" rel="stylesheet" />
		<link href="css/unison.css" rel="stylesheet" />
		<link href="css/calendar.css" rel="stylesheet" />
		<link href="css/calendar.less" rel="stylesheet/less" type="text/css" />
	<link href="css/font-awesome.min.css"
      type="text/css" rel="stylesheet" />
			<link rel="stylesheet" type="text/css" href="css/tree-control.css">
			<script type="text/javascript" src="js/less.min.js"></script>
<script type="text/javascript" src="js/underscore-min.js"></script>
		<script type="text/javascript" src="js/moment.min.js"></script>


    <!-- HTML5 Shim and Respond.js IE8 support of HTML5 elements and media queries -->
    <!-- WARNING: Respond.js doesn't work if you view the page via file:// -->
		<!--
		Need to figure out how to handle
		<panelGroup rendered="${commonUiHelper.isIE9()}">
      <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
   </panelGroup> -->

</head>
<body ng-controller="ScaleController as scale">
	<div class="container">
		<div ng-show="! scale.isSessionLoaded() && scale.appIsError">
			<div class="navbar navbar-default" role="navigation">
			  <div class="container-fluid">
			    <div class="navbar-header">
			      <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target=".navbar-collapse">
			        <span class="sr-only">Toggle navigation</span>
			        <span class="icon-bar"></span>
			        <span class="icon-bar"></span>
			        <span class="icon-bar"></span>
			      </button>
			      <img class="hidden-xs" src="images/logo-desktop.png"  width="85%" alt="scale"/>
			      <img class="visible-xs img-responsive" src="images/logo-mobile.png" alt="scale" />
			    </div>
			    <div class="navbar-collapse collapse">
			      <ul class="nav navbar-nav">

						</ul>

			    </div><!--/.nav-collapse -->
			  </div><!--/.container-fluid -->
			</div>
			<div class="jumbotron">
				<div class="alert alert-info" >
					<center><h3>Contacting Unison</h3>
					<b>If this screen does not disapear please contact your system administrator</b></center>
				</div>
			</div>
		</div>
		<div ng-show="! scale.isSessionLoaded() && ! scale.appIsError">
			<div class="navbar navbar-default" role="navigation">
			  <div class="container-fluid">
			    <div class="navbar-header">
			      <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target=".navbar-collapse">
			        <span class="sr-only">Toggle navigation</span>
			        <span class="icon-bar"></span>
			        <span class="icon-bar"></span>
			        <span class="icon-bar"></span>
			      </button>
			      <img class="hidden-xs" src="images/logo-desktop.png"  width="85%" alt="scale"/>
			      <img class="visible-xs img-responsive" src="images/logo-mobile.png" alt="scale" />
			    </div>
			    <div class="navbar-collapse collapse">
			      <ul class="nav navbar-nav">

						</ul>

			    </div><!--/.nav-collapse -->
			  </div><!--/.container-fluid -->
			</div>
			<div class="jumbotron">
				<center><h1>Logging In</h1></center>
				<center><h1><i class="fa fa-refresh fa-spin block"></i></h1></center>
			</div>
		</div>
		<div ng-show="scale.isSessionLoaded()">

	<!-- Static navbar -->
	<div class="navbar navbar-default" role="navigation">
	  <div class="container-fluid">
	    <div class="navbar-header">
	      <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target=".navbar-collapse">
	        <span class="sr-only">Toggle navigation</span>
	        <span class="icon-bar"></span>
	        <span class="icon-bar"></span>
	        <span class="icon-bar"></span>
	      </button>
	      <img class="hidden-xs" src="images/logo-desktop.png"  width="85%" alt="scale"/>
	      <img class="visible-xs img-responsive" src="images/logo-mobile.png" alt="scale" />
	    </div>
	    <div class="navbar-collapse collapse">
	      <ul class="nav navbar-nav">
					<li  ng-class="{active:scale.isSelectedTab('user')}">
					  <a href ng-click="scale.setSelectedTab('user')" style="color:#484848"  >{{ scale.displayName() }}</a>
					</li>
					<li ng-class="{active:scale.isSelectedTab('home')}" >
						<a href ng-click="scale.setSelectedTab('home')" style="color:#484848">Home</a>
					</li>
					
					
					<li ng-class="{active:scale.isSelectedTab('logout')}">
						<a href ng-click="scale.setSelectedTab('logout')" style="color:#484848">Logout</a>
					</li>
				</ul>

	    </div><!--/.nav-collapse -->
	  </div><!--/.container-fluid -->
	</div>

	<div class="jumbotron">
		<div ng-show="scale.isSelectedTab('user')">
	  	<h2>{{ scale.displayName() + "'s Profile" }}</h2>

			<div class="row" ng-show="scale.saveUserErrors.length > 0">
				<div class="alert alert-danger" >
					<b>There was a problem saving
						{{ scale.displayName() }}'s changes:</b>
					<ul>
							<li ng-repeat="msg in scale.saveUserErrors">{{ msg }}</li>
					</ul>
				</div>
			</div>

			<div class="row" ng-show="scale.saveUserSuccess">
				<div class="alert alert-success" >
					<b>{{ scale.displayName() }}'s changes saved successfully.  The changes may not be reflected in your account immediately.</b>

				</div>
			</div>

			<div class="row">
					<div class="col-md-6">
						<h3>Attributes</h3>

						<!-- For users that can be edited -->
						<div ng-show="scale.config.canEditUser" >
							<form name="saveUserForm">
								<div class="row" ng-repeat="attributeConfig in scale.config.attributes">
										<div class="col-md-4">{{ attributeConfig.displayName}}</div>
										<div class="col-md-4" ng-hide="attributeConfig.readOnly" ><input type="text" ng-model="scale.userToSave[attributeConfig.name].value"  aria-label="{{ attributeConfig.displayName }}" /></div>
										<div class="col-md-4" ng-show="attributeConfig.readOnly"><label>{{ scale.attributes[attributeConfig.name] }}</label></div>
								</div>
								<div  class="row">
									<input type="button" ng-disabled="scale.saveUserDisabled" class="btn btn-lg btn-primary" value="Save" ng-click="scale.saveUser()" />
								</div>
							</form>
						</div>

						<!-- For users that can NOT be edited -->
						<div ng-hide="scale.config.canEditUser">
							<div class="row" ng-repeat="attributeConfig in scale.config.attributes">
									<div class="col-md-4">{{ attributeConfig.displayName}}</div>
									<div class="col-md-4"><label>{{ scale.attributes[attributeConfig.name] }}</label></div>
								</div>
						</div>
					</div>

					<div class="col-md-6">
						<h3>Roles</h3>
						<div ng-hide="scale.currentGroups.length" class="alert alert-info" >{{ scale.displayName() }} has no roles assigned</div>

						<ul class="list-group" ng-show="scale.currentGroups.length">
								<li class="list-group-item" ng-repeat="groupName in scale.currentGroups">{{ groupName }}</li>
						</ul>

					</div>
			</div>

		</div>

		<div ng-show="scale.isSelectedTab('home')">
	  	<h2>{{ scale.config.frontPage.title }}</h2>
			{{ scale.config.frontPage.text }}

			<div class="row" ng-show="scale.config.showPortalOrgs">


				<treecontrol class="tree-light col-md-6"
				   tree-model="scale.portalOrgs"
				   options="scale.treeOptions"
				   on-selection="scale.selectPortalOrgs(node)"
				   selected-node="scale.portalOrgsSelectedNode"
					 expanded-nodes="scale.portalOrgsExpandedNodes">
				   {{node.name}}
				</treecontrol>

				<div class="col-md-6">
					<div class="alert alert-info " >
						<h3 >{{ scale.portalCurrentNode.name }}</h3>
						{{ scale.portalCurrentNode.description }}
					</div>
				</div>


			</div>
			<div class="row">
				<div class="col-sm-6 col-md-4" ng-repeat="url in scale.portalURLs track by $index">
					<div class="thumbnail" style="background:#eeeeee;">
						<a href="{{url.url}}" target="{{url.label}}"><img
							src="data:image/png;base64,{{url.icon}}" alt="{{url.label}}"/></a>
						<div class="caption">
							<center><h3>{{url.label}}</h3></center>
						</div>
					</div>
				</div>

				
			</div>

		</div>

	<!-- reports -->
	<div ng-show="scale.isSelectedTab('logout')">
		<div class="alert alert-danger" >
						<b>There are still items in your cart.  Don't forget to check them out to complete the requests.</b><br />
						<a href="" ng-click="scale.finishLogout()">Continue to logout</a>
					</div>
	</div>

	</div>

	<modal title="Processing" visible="scale.showModal">
		 <center><h1>{{ scale.modalMessage }}</h1>
     <h1><i class="fa fa-refresh fa-spin block"></i></h1></center>
   </modal>

</div>

	<!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
	<script src="js/jquery.min.js"></script>
	<!-- Include all compiled plugins (below), or include individual files as needed -->
	<script src="js/bootstrap.min.js"></script>

	<script src="js/angular.min.js"></script>

	<script type="text/javascript" src="js/angular-tree-control.js"></script>




<script src="js/scale.js"></script>

</body>
</html>
