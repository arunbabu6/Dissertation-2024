pipeline {
    agent any

    environment {
        DOCKER_IMAGE = 'ebpfztn'
        AWS_REGION = 'us-west-2'
        ECR_REPOSITORY = '913524928146.dkr.ecr.us-west-2.amazonaws.com/my-repo'
        PROJECT_DIR = '/opt/eBPFZTN'
        EKS_CLUSTER_NAME = 'my-cluster'
        EKS_NAMESPACE = 'myapps'
    }

    stages {
        stage('Prepare Environment') {
            steps {
                script {
                    if (fileExists(PROJECT_DIR)) {
                        sh "rm -rf ${PROJECT_DIR}/*"
                    } else {
                        sh "mkdir -p ${PROJECT_DIR}"
                    }
                    env.BUILD_ID = "${env.BUILD_NUMBER}"
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

        stage('Generate Image Hash') {
            steps {
                script {
                    def imageTag = "${DOCKER_IMAGE}:${BUILD_ID}"
                    echo "Build ID: ${BUILD_ID}"
                    def imageId = sh(returnStdout: true, script: "docker images -q ${imageTag}").trim()
                    echo "Image ID: ${imageId}" 
                    def imageHash = sh(returnStdout: true, script: "docker inspect --format='{{.RepoDigests}}' ${imageId} | grep -o 'sha256:[a-f0-9]\\{64\\}' | sha256sum | awk '{print \$1}'").trim()
                    echo "Generated Image Hash: ${imageHash}" // Troubleshoot: Print the generated image hash 
                    writeFile file: 'image-hash.txt', text: imageHash
                    echo "Image hash written to file: ${imageHash}"
                }
            }
        }

        stage('Test AWS CLI') {
            steps {
                withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'aws-credentials']]) {
                    sh 'aws secretsmanager list-secrets --region us-west-2'
                }
            }
        }


        stage('Store Image Hash to AWS Secrets Manager') {
            steps {
                withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'aws-credentials']]) {
                    script {
                        sh "env | grep AWS"
                        def hash = readFile 'image-hash.txt'
                        def imageTag = "${DOCKER_IMAGE}:${BUILD_ID}"
                        
                        // Recomputing the imageId since it is not persisting:check
                        def imageId = sh(returnStdout: true, script: "docker images -q ${imageTag}").trim()
                        def digest = sh(returnStdout: true, script: "docker inspect --format='{{.RepoDigests}}' ${imageId} | grep -o 'sha256:[a-f0-9]\\{64\\}'").trim()
                        
                        echo "Hash to store in AWS Secrets Manager: ${hash}"
                        echo "Digest to store in AWS Secrets Manager: ${digest}"

                        def secretName = "ImageHash-${BUILD_ID}"
                        
                        // Store both the custom hash and the image digest in AWS Secrets Manager
                        sh """
                        aws secretsmanager create-secret --name "ImageHash-${BUILD_ID}" \
                        --secret-string '{"hash": "${hash}", "digest": "${digest}"}' --region ${AWS_REGION} --force-overwrite-replica-secret
                        """
                    }
                }
            }
        }

        stage('Login to Amazon ECR') {
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

        stage('Push Image to ECR') {
            steps {
                script {
                    def imageTag = "${DOCKER_IMAGE}:${BUILD_ID}"
                    sh "docker tag ${imageTag} ${ECR_REPOSITORY}:${BUILD_ID}"
                    sh "docker push ${ECR_REPOSITORY}:${BUILD_ID}"
                }
            }
        }
 
        stage('Verify Image Hash using eBPF') { 
            steps {
            //    withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'aws-credentials']]) {
                    script {
                        // Environment variables for the script
                        env.BUILD_ID = "${BUILD_ID}"
                        env.IMAGE_TAG = "${DOCKER_IMAGE}:${BUILD_ID}"
                        //env.AWS_DEFAULT_REGION = "us-west-2"
                        //env.AWS_REGION = "us-west-2"

                        // Pull the image from ECR
                        sh "docker pull ${ECR_REPOSITORY}:${BUILD_ID}"

                        // Run Docker container in Jenkins server
                        def containerId = sh(returnStdout: true, script: "docker run -d ${DOCKER_IMAGE}:${BUILD_ID}").trim()
                        echo "Started container: ${containerId}"

                        // Calling Python script with a timeout of 60 seconds
                        def result = sh(returnStatus: true, script: "timeout 60 python3.8 /opt/hashcheck.py ${BUILD_ID} ${DOCKER_IMAGE}:${BUILD_ID}")
                        echo  "hashcheck Result: ${result}"

                        // Stop and remove the container after hash verification
                        sleep(60)
                        sh "docker stop ${containerId}"
                        sh "docker rm ${containerId}"
                                                

                        // If the script exits with a non-zero status
                        if (result != 0) {
                            error "Image hash verification failed in Jenkins."
                        }
                    }
                }
            }
 
        stage('Deploy eBPF DaemonSet') {
            steps {
                    withCredentials([file(credentialsId: 'kubeconfig1', variable: 'KUBECONFIG')]) {
                    script {
                        sh 'kubectl apply -f /opt/start-ebpf-monitor.yaml'
                        
                        // Waiting for the DaemonSet to be ready
                      //  sh 'kubectl rollout status daemonset/start-ebpf-monitor -n bcc-monitoring'
                    }
                }
            }
        }

        stage('Deploy App to Kubernetes') {
            steps {
                script {
                    // Defining the image tag using the repository URL and the BUILD_ID.
                    def imageTag = "${ECR_REPOSITORY}:${BUILD_ID}"
                    def buildId = "${BUILD_ID}"
                    echo "Build ID: ${buildId}"
                    withCredentials([file(credentialsId: 'kubeconfig1', variable: 'KUBECONFIG')]) {
                        
                        sh "sed -i 's|__IMAGE_TAG__|${buildId}|g' deployment.yaml"

                        sh "sed -i 's|__BUILD_ID__|${buildId}|g' deployment.yaml"
                        
                        sh "kubectl apply -f deployment.yaml -n ${env.EKS_NAMESPACE}"

                        // Monitor the deployment status until it is successfully rolled out.
                        sh "kubectl rollout status deployment/my-app-v1 -n ${EKS_NAMESPACE}"
                        // Wait for the application to be fully deployed
                        sh "kubectl rollout status deployment/my-app-v1 -n ${EKS_NAMESPACE}"
                    }                        
                }
            }
        }

        stage('Wait After App Deployment') {
            steps {
                script {
                    echo "Waiting for 30 seconds after app deployment before stopping eBPF monitoring"
                    sleep(30)  // Add the 30-second wait time after the application is deployed
                }
            }
        }

        stage('Delete start-ebpf') {
            steps {
                    withCredentials([file(credentialsId: 'kubeconfig1', variable: 'KUBECONFIG')]) {
                    script {
                        sh 'kubectl delete -f /opt/start-ebpf-monitor.yaml'
                        
                    }
                }
            }
        }
        
        stage('Stop eBPF Monitoring') {
            steps {
                withCredentials([file(credentialsId: 'kubeconfig1', variable: 'KUBECONFIG')]) {
                script {
                        sh 'kubectl apply -f /opt/stop-ebpf-monitor.yaml'
                        
                        // Waiting for the DaemonSet to be ready
                     //   sh 'kubectl rollout status daemonset/stop-ebpf-monitor -n bcc-monitoring'
                    }
                }
            }
        }

        stage('Delete stop-ebpf') {
            steps {
                    withCredentials([file(credentialsId: 'kubeconfig1', variable: 'KUBECONFIG')]) {
                    script {
                        sh 'kubectl delete -f /opt/stop-ebpf-monitor.yaml'
                        
                    }
                }
            }
        }        
    
        stage('Cleanup Docker Images') {
            steps {
                script {
                    def imageTag = "${DOCKER_IMAGE}:${BUILD_ID}"
                    sh "docker rmi ${ECR_REPOSITORY}:${BUILD_ID}"
                }
            }
        }

    }
}
