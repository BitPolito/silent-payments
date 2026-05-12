import { Route, Routes } from 'react-router-dom'
import bitpolitologo from './assets/bitpolito-logo-dark.png'
import bull_head from './assets/icon-bitpolito-bull-head.png'
import { Box, VStack, HStack, Button } from '@chakra-ui/react'
import { useState } from 'react'
import TestModal from './scenes/Tests'
import GenerateAddr from './scenes/GenerateAddr'

function AnimatedButton({ children, action }) {
  return (
    <Button
      variant="outline"
      borderColor="white"
      borderWidth="2px"
      color="white"
      fontSize="2xl"
      fontWeight="bold"
      borderRadius="md"
      width="300px"
      height="100px"
      bg="transparent"
      transition="transform 0.2s ease-in-out"
      _hover={{
        transform: 'scale(1.05)',
        bg: 'transparent', 
      }}
      _active={{
        transform: 'scale(0.98)', 
      }}
      onClick={action}
    >
      {children}
    </Button>
  );
}

function App() {

	const [showTest, setShowTests] = useState(false)
	const [ShowAddr, setShowAddr] = useState(false)
	const [isVanity, setIsVanity] = useState(false)

    return (
    <Routes>
        <Route 
        path="/" 
        element={
            <Box w="100vw" minH="100vh" mx="auto" backgroundColor={"#001CE0"} position="relative">
                
                <Box 
                    position="absolute"
                    as="img"
                    ml={7} mt={7} 
                    top={0} left={0} 
                    w="100px" h="100px" 
                    alt="BitPolito Bull Head"
                    bg={"rgba(255, 255, 255, 0.7)"}
                    src={bull_head}
                    zIndex={2} 
                />

                <VStack gap={4} align="center" py={10} width="100%">
                    <Box 
                        mt={220}
                        as="img"
                        src={bitpolitologo}
                        alt="BitPolito Logo"
                        h="120px"
                        objectFit="contain"
                    />

                    <Box mt={10} mb={3} color={"white"} fontSize="4xl" fontWeight="bold">
                        Silent Payments Implementation
                    </Box>

					<HStack gap={16} width="100%" justify="center" mt={6}>

						<AnimatedButton action={() => {setShowTests(true);}}>
							Run tests
						</AnimatedButton>

						<AnimatedButton action={() => {setShowAddr(true); setIsVanity(false)}}>
							Generate address
						</AnimatedButton>

						<AnimatedButton action={() => {setShowAddr(true); setIsVanity(true)}}>
							Generate vanity address
						</AnimatedButton>

                	</HStack>
                </VStack>

				<TestModal
					isOpen={showTest}
					onClose={() => setShowTests(false)}
				/>
				<GenerateAddr
					isOpen={ShowAddr}
					onClose={() => setShowAddr(false)}
					isVanity={isVanity}
				/>

            </Box>
        } 
        />
    </Routes>
    )
}

export default App