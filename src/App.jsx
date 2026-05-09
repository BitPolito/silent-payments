import { useState, useEffect } from 'react'
import './App.css'
import { Route, Routes } from 'react-router-dom'
import bitpolitologo from './assets/bitpolito-logo-dark.png'
import { Box, VStack, Heading, List, Spinner, HStack, Text, Button } from '@chakra-ui/react'

function TestList() {
  const [tests, setTests] = useState([])
  const [testFinished, setTestFinished] = useState(false)
  const [loading, setLoading] = useState(true)
  const [testResults, setTestResults] = useState({});
  const [testType, setTestType] = useState("");

  useEffect(() => {
    fetch('/api/get_all_tests')
      .then((response) => response.json())
      .then((data) => {
        const testArray = data["TEST LIST"]; 
        setTests(testArray);
        setLoading(false);
      })
      .catch((error) => {
        console.error("Errore durante il recupero dei test:", error);
        setLoading(false);
      });
  }, []);

  const handleSendTest = (testId) => {
    console.log(`Esecuzione Send Test per ID: ${testId}...`);
    fetch(`/api/single_test/send/${testId}`)
      .then(response => response.json())
      .then(data => {
        console.log(`Risultato Send Test ${testId}:`, data);
		setTestType("send");
		setTestResults(data);
        setTestFinished(true);
      })
      .catch(error => {console.error("Errore Send Test:", error); setTestFinished(true);});
  };

  const handleReceiveTest = (testId) => {
    console.log(`Esecuzione Receive Test per ID: ${testId}...`);
    fetch(`/api/single_test/receive/${testId}`)
      .then(response => response.json())
      .then(data => {
        console.log(`Risultato Receive Test ${testId}:`, data);
		setTestType("receive");
		setTestResults(data);
        setTestFinished(true);
      })
      .catch(error => {console.error("Errore Receive Test:", error); setTestFinished(true);});
  };

  return (
    <Box p={5} w="100%" maxW="800px">
      <Heading mb={4}>Test List</Heading>
      
      {loading ? (
        <Spinner /> 
      ) : (
        <VStack align="stretch" spaceY={3}>
          <List.Root spaceY={3}> 
            {tests.map((test, index) => (
              <List.Item key={index} p={3} bg="gray.100" borderRadius="md">
                
                <HStack justify="space-between" w="100%">
                  
                  <Text flex="1" fontWeight="medium">
                    {test}
                  </Text>
                  
                  <HStack gap={2}>
                    <Button 
                      size="sm" 
                      bg="blue.500" 
                      color="white" 
                      onClick={() => handleSendTest(index)}
                    >
                      Send Test
                    </Button>
                    
                    <Button 
                      size="sm" 
                      bg="green.500" 
                      color="white" 
                      onClick={() => handleReceiveTest(index)}
                    >
                      Receive Test
                    </Button>
                  </HStack>

                </HStack>
				
				{testFinished && testResults.test_id === index && (
					testType === "send" ? (
						<VStack align="start" spacing={3} bg="gray.50" p={4} borderRadius="md" w="full">
							<Text fontSize="md" fontWeight="bold" color={testResults.test_passed ? "green.600" : "red.600"}>
								Send Test Result: {testResults.test_passed ? 'Passed' : 'Failed'} 
								{testResults.test_id === 25 ? ' ; Tester detected zero key sum' : ''}
							</Text>

							{/* Ciclo su tutti gli expected_outputs */}
							{testResults.expected_outputs && testResults.expected_outputs.map((expectedOutput, index) => {
								// Recupero l'output ricevuto corrispondente tramite l'indice
								const receivedOutput = testResults.outputs ? testResults.outputs[index] : null;

								return (
									<VStack 
										key={index} 
										align="start" 
										spacing={1} 
										bg="white" 
										p={3} 
										borderRadius="md" 
										borderWidth="1px" 
										borderColor="gray.200"
										w="full"
									>
										<Text fontSize="sm" fontWeight="semibold" color="gray.700">
											Output #{index + 1}
										</Text>
										<Text fontSize="sm" color="gray.600">
											Received: {receivedOutput ? JSON.stringify(receivedOutput) : 'N/A'}
										</Text>
										<Text fontSize="sm" color="gray.600">
											Expected: {JSON.stringify(expectedOutput)}
										</Text>
									</VStack>
								);
							})}
						</VStack>
					) : (

						<VStack align="start" spacing={3} bg="gray.50" p={4} borderRadius="md" w="full">
							<Text fontSize="md" fontWeight="bold" color={testResults.test_passed ? "green.600" : "red.600"}>
								Receive Test Result: {testResults.test_passed ? 'Passed' : 'Failed'}
							</Text>

							{/* Ciclo su tutti gli expected_outputs */}
							{testResults.expected_outputs && testResults.expected_outputs.map((expectedOutput, index) => {
								// Recupero l'output ricevuto corrispondente basandomi sull'indice
								const receivedOutput = testResults.outputs ? testResults.outputs[index] : null;

								return (
									<VStack 
										key={index} // La key è obbligatoria in React quando si usa .map()
										align="start" 
										spacing={1} 
										bg="white" 
										p={3} 
										borderRadius="md" 
										borderWidth="1px" 
										borderColor="gray.200"
										w="full"
									>
										<Text fontSize="sm" fontWeight="semibold" color="gray.700">
											Output #{index + 1}
										</Text>

										<Text fontSize="sm" color="gray.600">
											Received private key tweak: {receivedOutput ? JSON.stringify(receivedOutput.priv_key_tweak) : 'N/A'}
										</Text>
										<Text fontSize="sm" color="gray.600">
											Expected private key tweak: {JSON.stringify(expectedOutput.priv_key_tweak)}
										</Text>
										
										<Text fontSize="sm" color="gray.600" mt={2}>
											Received public key: {receivedOutput ? JSON.stringify(receivedOutput.pub_key) : 'N/A'}
										</Text>
										<Text fontSize="sm" color="gray.600">
											Expected public key: {JSON.stringify(expectedOutput.pub_key)}
										</Text>
									</VStack>
								);
							})}
						</VStack>
					)
				)}
              </List.Item>
            ))}
          </List.Root>
        </VStack>
      )}
    </Box>
  )
}

function App() {

	return (
	<Routes>
		<Route 
		path="/" 
		element={
			<VStack spacing={3}>

				<Box backgroundColor="#001CE0" p={4}>
					Silent Payments Implementation
				</Box>
				
				<Box 
					as="img"
					src={bitpolitologo}
					alt="BitPolito Logo"
					h="18px"
					objectFit="contain"
				/>

				<TestList />

			</VStack>
		} 
		/>
	</Routes>
	)
}

export default App