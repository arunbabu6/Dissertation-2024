pipeline {
    agent any

    environment {
        DOCKER_IMAGE = 'ebpfztn'  // Ensure this is lowercase as per Docker naming rules: Learning
        AWS_REGION = 'us-west-2'
        ECR_REPOSITORY = '533267172050.dkr.ecr.us-west-2.amazonaws.com/my-repo'
        PROJECT_DIR = '/opt/eBPFZTN'
        EKS_CLUSTER_NAME = 'my-cluster'
        EKS_NAMESPACE = 'jenkins'

    }

    stages {
        stage('Prepare Environment') {
            steps {
                script {
                    // Clean up the project directory
                    if (fileExists(PROJECT_DIR)) {
                        sh "rm -rf ${PROJECT_DIR}/*"
                    } else {
                        sh "mkdir -p ${PROJECT_DIR}"
                    }
                }
            }
        }
        stage('Clone Repository') {
            steps {
                git url: 'https://github.com/arunbabu6/Dissertation-2024.git', branch: 'main'
            }
        }

        stage('Build Docker Image') {
            steps {
                sh "chmod +x ./build.sh"
                sh "./build.sh"
            }
        }

        stage('Generate Image Hash') { // Generate Hash 
            steps {
                script {
                    def imageTag = "${DOCKER_IMAGE}:${BUILD_ID}"
                    def imageId = sh(returnStdout: true, script: "docker images -q ${imageTag}").trim()
                    def imageHash = sh(returnStdout: true, script: "docker inspect --format='{{.Id}}' ${imageId} | sha256sum | awk '{print \$1}'").trim()
                    writeFile file: 'image-hash.txt', text: imageHash
                }
            }
        }

        stage('Store Image Hash to AWS Secrets Manager') {   // Store Hash using aws-credentials
            steps {
                withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'aws-credentials']]) {
                script {
                    def timestamp = new Date().format("yyyyMMddHHmmss")
                    env.IMAGE_HASH_TIMESTAMP = timestamp  // Store the timestamp in an environment variable
                    def hash = readFile 'image-hash.txt'
                    def secretName = "ImageHash-${BUILD_ID}-${timestamp}"
                    sh """
                    aws secretsmanager create-secret --name ${secretName} \
                    --secret-string ${hash} --region ${AWS_REGION}
                    """
                    }
                }
            }
        }

        stage('Login to Amazon ECR') {  // ECR Login with aws-credentials
            steps {
                withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'aws-credentials']]) {
                    script {
                        sh """
                        aws ecr get-login-password --region ${AWS_REGION} | \
                        docker login --username AWS --password-stdin ${ECR_REPOSITORY}
                        """
                    }
                }
            }
        }

        stage('Push Image to ECR') { // Image Push
            steps {
                script {
                    def imageTag = "${DOCKER_IMAGE}:${BUILD_ID}"
                    sh "docker tag ${imageTag} ${ECR_REPOSITORY}:${BUILD_ID}"
                    sh "docker push ${ECR_REPOSITORY}:${BUILD_ID}"
                }
            }
        }
        
        stage('Cleanup Image-hash.txt') { // Cleanup 
            steps {
                sh "rm -f image-hash.txt"
            }
        }

        stage('Verify Image Hash Before Deploy') {
            steps {
                withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'aws-credentials']]) {
                script {
                    def timestamp = env.IMAGE_HASH_TIMESTAMP  // Retrieve the timestamp from the environment variable

                    def storedHash = sh(returnStdout: true, script: """
                        aws secretsmanager get-secret-value --secret-id ImageHash-${BUILD_ID}-${timestamp} --region ${AWS_REGION} --query 'SecretString' --output text
                    """).trim()

                    echo "Stored Hash: ${storedHash}"

                    def imageTag = "${DOCKER_IMAGE}:${BUILD_ID}"
                    def imageId = sh(returnStdout: true, script: "docker images -q ${imageTag}").trim()
                    def currentHash = sh(returnStdout: true, script: "docker inspect --format='{{.Id}}' ${imageId} | sha256sum | awk '{print \$1}'").trim()
                    echo "Current Hash: ${currentHash}"
                    if (currentHash != storedHash) {
                        error "Image hash verification failed! The image may have been tampered with."
                    } else {
                        echo "Image hash verified successfully."
                        }
                    }
                }
            }
        }

        stage('Deploy App to Kubernetes') { 
            steps {
                script {
                    def interpolatedBuildId = "${DOCKER_IMAGE}:${BUILD_ID}"
                    withCredentials([file(credentialsId: 'kubeconfig1', variable: 'KUBECONFIG')]) {
                        sh "sed -i 's/__IMAGE_TAG__/${interpolatedBuildId}/' deployment.yaml"
                        sh "kubectl apply -f deployment.yaml -n ${env.EKS_NAMESPACE}"
                    }
                }
            }
        }
    }
}

