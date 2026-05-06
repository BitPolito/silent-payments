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
						<VStack align="start" spacing={1} bg="gray.50" p={2} borderRadius="md">

							<Text fontSize="sm" color="black.500">
								Send Test Result: {testResults.test_passed ? 'Passed' : 'Failed'}
							</Text>
							<Text fontSize="sm" color="black.500">
								Output: {JSON.stringify(testResults.outputs)}
							</Text>
							<Text fontSize="sm" color="black.500">
								Expected: {JSON.stringify(testResults.expected_outputs)}
							</Text>
						</VStack>
					) : (
						<VStack align="start" spacing={1} bg="gray.50" p={2} borderRadius="md">
							<Text fontSize="sm" color="black.500">
								Receive Test Result: {testResults.test_passed ? 'Passed' : 'Failed'}
							</Text>
							<Text fontSize="sm" color="black.500">
								Received private key tweak: {JSON.stringify(testResults.outputs[0].priv_key_tweak)}
							</Text>
							<Text fontSize="sm" color="black.500">
								Expected private key tweak: {JSON.stringify(testResults.expected_outputs[0].priv_key_tweak)}
							</Text>
							<Text fontSize="sm" color="black.500">
								Received public key: {JSON.stringify(testResults.outputs[0].pub_key)}
							</Text>
							<Text fontSize="sm" color="black.500">
								Expected public key: {JSON.stringify(testResults.expected_outputs[0].pub_key)}
							</Text>
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