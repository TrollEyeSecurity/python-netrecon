pipeline {
    agent  {
        label 'production'
    }
    stages {
        stage('Build and push image') {
            steps {
                echo 'Starting to build docker image'
                script {
                    sh 'docker rmi "trolleye/netrecon:latest" || echo "netrecon:latest image does not exist"'
                    docker.withRegistry('https://index.docker.io/v1/', 'DockerHub') {
                    def customImage = docker.build("trolleye/netrecon:latest")
                    customImage.push()
                    }
                }
            }
        }
    }
}
