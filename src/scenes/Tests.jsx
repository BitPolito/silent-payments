import { useState, useEffect } from 'react';
import { Box, VStack, HStack, Text, Button, Input, Spinner, Separator } from '@chakra-ui/react';

export default function TestModal({ isOpen, onClose }) {
    
	// --- STATES ---
    const [testType, setTestType] = useState('send');
    const [testId, setTestId] = useState('');
    
    const [loading, setLoading] = useState(false);
    const [testFinished, setTestFinished] = useState(false);
    const [testResults, setTestResults] = useState(null);

    const [showAllTests, setShowAllTests] = useState(false);
    const [tests, setTests] = useState([]);

    useEffect(() => {
        if (isOpen) {
            const fetchTests = async () => {
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
            };
            fetchTests();
        } else {
            setTestFinished(false);
            setTestResults(null);
            setShowAllTests(false);
            setTestId('');
        }
    }, [isOpen]);

	const handleSendTest = async (testId) => {
		
		setLoading(true);
		fetch(`/api/single_test/send/${testId}`)
			.then(response => response.json())
			.then(data => {
				setTestType("send");
				setTestResults(data);
				setTestFinished(true);
				setLoading(false);
			})
			.catch(error => {console.error("Errore Send Test:", error); setTestFinished(true); setLoading(false);});
	};

	const handleReceiveTest = async (testId) => {
		setLoading(true);

		fetch(`/api/single_test/receive/${testId}`)
			.then(response => response.json())
			.then(data => {
				setTestType("receive");
				setTestResults(data);
				setTestFinished(true);
				setLoading(false);
			})
			.catch(error => {console.error("Errore Receive Test:", error); setTestFinished(true); setLoading(false);});
	};

    const executeTestFromInput = () => {
        const id = parseInt(testId);

        if (isNaN(id)) return;
        
        if (testType === 'send') {
            handleSendTest(id);
        } else {
            handleReceiveTest(id);
        }
    };

    if (!isOpen) return null;

    return (
        <Box 
            position="fixed" top={0} left={0} w="100vw" h="100vh" 
            bg="rgba(0, 0, 0, 0.6)"
            backdropFilter="blur(4px)" zIndex={9999} 
            display="flex" alignItems="center" justifyContent="center"
            onClick={onClose} 
        >
            <Box 
                bg="white" border="4px solid #001CE0" borderRadius="2xl" p={8} w="100%" 
                maxW="700px" maxH="85vh" overflowY="auto" position="relative"
                onClick={(e) => e.stopPropagation()} 
                boxShadow="2xl"
                color="black" >
                <Button position="absolute" top={4} right={4} size="sm" variant="ghost" onClick={onClose}>
                    X
                </Button>

                <VStack gap={6} align="stretch">
                    <Text fontSize="2xl" fontWeight="bold" color="#001CE0" textAlign="center">
                        Silent Payments Tests
                    </Text>

                    <HStack gap={4}>
                        <Box as="select" value={testType} onChange={(e) => setTestType(e.target.value)}
                             p={2} borderWidth="1px" borderRadius="md" borderColor="gray.300" flex="1"
                        >
                            <option value="send">Send Test</option>
                            <option value="receive">Receive Test</option>
                        </Box>

						<Input 
							type="number" 
							placeholder="Enter Test ID" 
							value={testId === 'invalid' ? '' : testId} 
							onChange={(e) => {
								const val = e.target.value;
								if (val === '') {
									setTestId('');
									return;
								}
								const num = parseInt(val);
								if (num < 0 || num >= 26) {
									setTestId('invalid');
								} else {
									setTestId(val);
								}
							}} 
							flex="1"
						/>

                        <Button 
                            bg="#001CE0" color="white" _hover={{ bg: "#0014a8" }}
                            onClick={executeTestFromInput} disabled={loading || testId === 'invalid'}
                        >
                            Run
                        </Button>
                    </HStack>

                    <Button 
                        variant="outline" colorPalette="blue" size="sm" w="full" 
                        onClick={() => setShowAllTests(!showAllTests)}
                    >
                        {showAllTests ? "Hide All Tests" : "See All Available Tests"}
                    </Button>

                    {showAllTests && (
                        <Box bg="gray.50" p={4} borderRadius="md" borderWidth="1px" maxH="200px" overflowY="auto">
                            {tests.length === 0 ? (
                                <Text fontSize="sm" color="gray.500" textAlign="center">Loading tests...</Text>
                            ) : (
                                <VStack align="stretch" gap={2}>
                                    {tests.map((t) => (
                                        <HStack key={t} justify="space-between" p={2} bg="white" borderRadius="sm" borderWidth="1px">
                                            <Text fontSize="sm" fontWeight="medium">ID: {t}</Text>
                                        </HStack>
                                    ))}
                                </VStack>
                            )}
                        </Box>
                    )}

                    <Separator />

				{loading ? (
					<VStack py={10}>
						<Spinner size="xl" color="#001CE0" borderWidth="4px" />
						<Text color="gray.500" mt={4}>Executing test...</Text>
					</VStack>
				) : testId === 'invalid' ? (
					<HStack py={10} justify="center" bg="red.50" borderRadius="md" border="1px dashed" borderColor="red.300">
						<Text color="red.500" fontWeight="bold"> Invalid test ID (Must be between 0 and 25)</Text>
					</HStack>
				) : (
				testFinished && testResults && (
					<VStack align="start" gap={3} bg="gray.50" p={4} borderRadius="md" w="full" position="relative">
						
						<HStack justify="space-between" w="full" pr={8}> 
							<Text fontSize="md" fontWeight="bold" color={testResults.test_passed ? "green.600" : "red.600"}>
								Test ID: {testResults.test_id} | Result: {testResults.test_passed ? 'Passed' : 'Failed'}
								{testResults.test_id === 25 ? ' (Zero key sum detected)' : ''}
							</Text>

							<Button 
								position="absolute" 
								top={2} 
								right={2} 
								size="sm" 
								variant="ghost" 
								onClick={() => {
									setTestResults(null);
									setTestFinished(false);
								}}
							>
								X
							</Button>
						</HStack>

						{testResults.expected_outputs && testResults.expected_outputs.map((expectedOutput, index) => {
							const receivedOutput = testResults.outputs ? testResults.outputs[index] : null;

							return (
								<Box key={index} w="full">
									<VStack 
										align="start" 
										gap={2} 
										bg="white" 
										p={4} 
										borderRadius="md" 
										borderWidth="1px" 
										borderColor="gray.200" 
										w="full"
									>
										<Text fontSize="sm" fontWeight="bold" color="blue.600">
											Output #{index + 1}
										</Text>

										{testType === "send" ? (
											<VStack align="start" gap={2} w="full">
												<Box w="full">
													<Text fontSize="sm" fontWeight="bold" color="gray.700">Received:</Text>
													<Text fontSize="sm" color="gray.600" wordBreak="break-all" bg="gray.50" p={2} borderRadius="md" fontFamily="monospace">
														{receivedOutput ? JSON.stringify(receivedOutput) : 'N/A'}
													</Text>
												</Box>
												<Box w="full">
													<Text fontSize="sm" fontWeight="bold" color="gray.700">Expected:</Text>
													<Text fontSize="sm" color="gray.700" wordBreak="break-all" bg="gray.50" p={2} borderRadius="md" fontFamily="monospace">
														{JSON.stringify(expectedOutput)}
													</Text>
												</Box>
											</VStack>
										) : (
											<VStack align="start" gap={2} w="full">
												<Box w="full">
													<Text fontSize="sm" fontWeight="bold" color="gray.700">Received public key:</Text>
													<Text fontSize="sm" color="gray.700" wordBreak="break-all" bg="gray.50" p={2} borderRadius="md" fontFamily="monospace">
														{receivedOutput ? receivedOutput.pub_key : 'N/A'}
													</Text>
												</Box>
												<Box w="full">
													<Text fontSize="sm" fontWeight="bold" color="gray.700">Expected public key:</Text>
													<Text fontSize="sm" color="gray.700" wordBreak="break-all" bg="gray.50" p={2} borderRadius="md" fontFamily="monospace">
														{expectedOutput.pub_key}
													</Text>
												</Box>
												<Box w="full">
													<Text fontSize="sm" fontWeight="bold" color="gray.700">Received private key tweak:</Text>
													<Text fontSize="sm" color="gray.700" wordBreak="break-all" bg="gray.50" p={2} borderRadius="md" fontFamily="monospace">
														{receivedOutput ? receivedOutput.priv_key_tweak : 'N/A'}
													</Text>
												</Box>
												<Box w="full">
													<Text fontSize="sm" fontWeight="bold" color="gray.700">Expected private key tweak:</Text>
													<Text fontSize="sm" color="gray.700" wordBreak="break-all" bg="gray.50" p={2} borderRadius="md" fontFamily="monospace">
														{expectedOutput.priv_key_tweak}
													</Text>
												</Box>
											</VStack>
										)}
									</VStack>
								</Box>
							);
						})}
					</VStack>
				)
			)}
                </VStack>
            </Box>
        </Box>
    );
}