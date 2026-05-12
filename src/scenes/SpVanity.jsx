import { useState, useEffect } from 'react';
import { Box, VStack, HStack, Text, Button, Input, Spinner, Separator, Select, Checkbox } from '@chakra-ui/react';
import iconDownload from '../assets/icon-download.png'
import bull_head from '../assets/icon-bitpolito-bull-head.png'
import { BiDockBottom } from 'react-icons/bi';
import { jsPDF } from 'jspdf';

export default function SpVanity({ isOpen, onClose }) {

	const [loading, setLoading] = useState(false);
	const [testFinished, setTestFinished] = useState(false);
	const [testResults, setTestResults] = useState([]);

	const [pattern, setPattern] = useState("");
	const [mode, setMode] = useState("contains");
	const [threads, setThreads] = useState(0);
	const [testnet, setTestnet] = useState(0);
	const [forcePython, setForcePython] = useState(0);

	const [isDownloading, setIsDownloading] = useState(false)

	if (!isOpen) return null;

	const handleDownloadQr = async () => {
		setIsDownloading(true);
		fetch('/api/qr_code')
		.then(async response => {
			if (!response.ok) {
				throw new Error('Error while fetching the qr file');
			}

			const blob = await response.blob();
			const tempUrl = URL.createObjectURL(blob);

			const link = document.createElement('a');
			link.href = tempUrl;
			link.download = 'silent_payments_qr.png';
			
			document.body.appendChild(link);
			link.click();
			document.body.removeChild(link);

			setTimeout(() => URL.revokeObjectURL(tempUrl), 100);
		})
		.catch(error => {
			console.log("Error while fetching qr code: ", error);
		})
		.finally(
			setIsDownloading(false)
		)
	}

	const handleDownloadResults = () => {
		const doc = new jsPDF()

		doc.setFontSize(18);
		doc.addImage(bull_head, "PNG", 14, 10, 40, 40);
		
		doc.setFont("helvetica", "bold");
		doc.text("Results", 14, 60);

		let posY = 70;

		const drawData = (label, value) => {
			
			doc.setFontSize(10); 
			doc.setFont("helvetica", "bold");
			doc.setTextColor(74, 85, 104); 
			doc.text(`${label}:`, 14, posY);

			posY += 5;

			doc.setFontSize(10);
			doc.setFont("courier", "normal"); 
			doc.setTextColor(113, 128, 150);

			const maxBoxWidth = 180; 
			const padding = 6;
		
			const splitText = doc.splitTextToSize(String(value), maxBoxWidth - (padding * 2));

			const lineHeight = 5;
			const boxHeight = (splitText.length * lineHeight) + (padding * 2);

			doc.setFillColor(247, 250, 252);
			doc.roundedRect(14, posY, maxBoxWidth, boxHeight, 2, 2, 'F');

			doc.text(splitText, 14 + padding, posY + padding + 3.5);

			posY += boxHeight + 10; 
		};

		drawData("Vanity Address", testResults.addresses[0]);
		drawData("Spend Private Key", testResults.key_material.spend_priv_key);
		drawData("Scan Private Key", testResults.key_material.scan_priv_key);

		doc.save("Address_Results.pdf");

	}

	const handleVanityTest = async () => {
		setLoading(true);
		fetch(`/api/vanity_address/${pattern}/${mode}/${threads}/${testnet}/${forcePython}`)
			.then(async response => {
				if (!response.ok) {
					const errorText = await response.text();
					throw new Error(`Server failed with status ${response.status}: ${errorText}`);
				}
				return response.json();
			})
			.then(data => {
				console.log(data);
				setTestResults(data);
				setPattern("");
			})
			.catch(error => {
				console.log("Error while fetching: ", error);
				setLoading(false);
				setTestFinished(true);
			})
			.finally(() => {
				setLoading(false);
				setTestFinished(true);
			})

	}

	const closePage = () => {
		setLoading(false);
		setTestResults([]);
		setPattern("");
		setTestFinished(false);
		setMode("contains");
		setForcePython(0);
		setTestnet(0);
		setThreads(0);
		setIsDownloading(false);
		onClose();
	}

	return (
	<Box
		position="fixed" top={0} left={0} w="100vw" h="100vh"
		bg="rgba(0, 0, 0, 0.6)"
		backdropFilter="blur(4px)" zIndex={9999}
		display="flex" alignItems="center" justifyContent="center"
		onClick={closePage}
	>
		<Box
		bg="white" border="4px solid #001CE0" borderRadius="2xl" p={8} w="100%"
		maxW="700px" maxH="85vh" overflowY="auto" position="relative"
		onClick={(e) => e.stopPropagation()}
		boxShadow="2xl"
		color="black"
		>
		<Button position="absolute" top={4} right={4} size="sm" variant="ghost" onClick={closePage}>
			X
		</Button>

		<VStack gap={6} align="stretch">
			<Text fontSize="2xl" fontWeight="bold" color="#001CE0" textAlign="center">
				Generate your vanity address
			</Text>

			<HStack w="full">
				<Input
					type="text"
					placeholder="Enter the pattern"
					value={pattern}
					onChange={(e) => setPattern(e.target.value)}
					flex="1"
				/>
				<Button
					bg="#001CE0"
					color="white"
					_hover={{ bg: "#0014a8" }}
					onClick={handleVanityTest}
					disabled={loading || pattern.trim() === ""}
				>
					Generate
				</Button>
			</HStack>

			<Separator />

			{loading ? (

			<VStack py={10}>
				<Spinner size="xl" color="#001CE0" borderWidth="4px" />
				<Text color="gray.500" mt={4}>Generating address...</Text>
			</VStack>

			) : (
			testFinished && testResults && (
				<VStack align="start" gap={4} bg="gray.50" p={4} borderRadius="md" w="full" position="relative">
				<HStack justify="space-between" w="full" pr={8}>
				
					<Text fontSize="sm" color="gray.500" fontWeight="medium">
						Elapsed time: {testResults.elapsed ? `${testResults.elapsed.toFixed(3)} s` : "N/A"}
					</Text>

					<Button
					position="absolute"
					top={1}
					right={1}
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


					<Box w="full">
						{testResults && (
						<VStack
							align="start"
							gap={3}
							mt={2}
							bg="white"
							p={4}
							borderRadius="md"
							borderWidth="1px"
							borderColor="gray.200"
							w="full"
						>
							{testResults.message && (
							<Text fontSize="md" fontWeight="bold" color="green.600">
								{testResults.message}
							</Text>
							)}

							{testResults.addresses && testResults.addresses.length > 0 && (
							<Box w="full">
								<Text fontSize="sm" fontWeight="bold" color="gray.700">
									Generated Address:
								</Text>
								<Text
								fontSize="sm"
								color="gray.600"
								wordBreak="break-all"
								bg="gray.50"
								p={2}
								borderRadius="md"
								fontFamily="monospace"
								>
									{testResults.addresses[0]}
								</Text>
							</Box>
							)}

							{testResults.key_material && (
							<>
								<Box w="full">
								<Text fontSize="sm" fontWeight="bold" color="gray.700">
									Scan Private Key:
								</Text>
								<Text
									fontSize="sm"
									color="gray.600"
									wordBreak="break-all"
									bg="gray.50"
									p={2}
									borderRadius="md"
									fontFamily="monospace"
								>
									{testResults.key_material.scan_priv_key}
								</Text>
								</Box>

								<Box w="full">
								<Text fontSize="sm" fontWeight="bold" color="gray.700">
									Spend Private Key:
								</Text>
								<Text
									fontSize="sm"
									color="gray.600"
									wordBreak="break-all"
									bg="gray.50"
									p={2}
									borderRadius="md"
									fontFamily="monospace"
								>
									{testResults.key_material.spend_priv_key}
								</Text>
								</Box>
							</>
							)}

								<Box 
									position="relative"
									left={55}
									zIndex={10}
								>
									<HStack gap={5}>
										<Button
											onClick={handleDownloadQr}
											loading={isDownloading}
											loadingText="Downloading..."
											backgroundColor={"#001CE0"}
											color="white"
											size="lg"
											variant="solid"
										>
											<img 
												src={iconDownload} 
												alt="download icon" 
												style={{ width: '20px', height: '20px', marginRight: '2px' }} 
											/>
											Download Qr Code
										</Button>

										<Button
											onClick={handleDownloadResults}
											loading={isDownloading}
											loadingText="Downloading..."
											backgroundColor={"#001CE0"}
											color="white"
											size="lg"
											variant="solid"
										>
											<img 
												src={iconDownload} 
												alt="download icon" 
												style={{ width: '20px', height: '20px', marginRight: '2px' }} 
											/>
											Download Results
										</Button>

									</HStack>
								</Box>

						</VStack>
						)}
					</Box>

				</VStack>
			)
			)}
		</VStack>
		</Box>
	</Box>
	);
}