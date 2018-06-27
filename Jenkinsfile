#!/usr/bin/env groovy
/*
* Testing script for Dev, to run from Jenkins CI
* 
* Copyright (C) Mellanox Technologies Ltd, 2001-2018. ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

node('master') {
	deleteDir()
	checkout scm
	dir('swx_ci') {
		checkout([$class: 'GitSCM', 
				extensions: [[$class: 'CloneOption',  shallow: true]], 
				userRemoteConfigs: [[ url: 'https://github.com/Mellanox/swx_ci']]
				])
	}
	def funcs = load "${env.WORKSPACE}/swx_ci/template/functions.groovy"
	def jjb_pipeFile = funcs.getProjFile("proj_pipeline.groovy")
	evaluate(readFile("${jjb_pipeFile}"))
}
