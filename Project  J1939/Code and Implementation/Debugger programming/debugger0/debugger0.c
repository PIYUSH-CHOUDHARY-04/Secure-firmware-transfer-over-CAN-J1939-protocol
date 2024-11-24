#define GPIO_PTR GPIOA
static void Display(uint8_t num){

	HAL_GPIO_WritePin(GPIO_PTR, num, GPIO_PIN_SET);
	HAL_Delay(5000);
	HAL_GPIO_WritePin(GPIO_PTR, num, GPIO_PIN_RESET);
	HAL_Delay(5000);
}