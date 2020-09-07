//
// Created by Laura Lemmi on 07/09/2020.
//

#include "GameBoard.h"
#include "../Libraries/Constant.h"
#include <iostream>

GameBoard::GameBoard() {

    gameMatrix = new int*[ROWSNUMBER];
    for(int i = 0; i < ROWSNUMBER; i++) {
        gameMatrix[i] = new int[COLUMNSNUMBER];
        for(int j = 0; j < COLUMNSNUMBER; j++)
            gameMatrix[i][j] = -1;
    }

}

GameBoard::~GameBoard() {

    for(int i = 0; i < ROWSNUMBER; i++)
        delete [] gameMatrix[i];
    delete [] gameMatrix;
}


int GameBoard::insertCoordinateInBoard(uint8_t x, uint8_t y, int value) {

    if(x < 1 || x > 6 || y < 1 || y > 7) {
        std::cout << "Error! Coordinate not valid" << std::endl;
        return -1;
    }
    x--;
    y--;

    if(gameMatrix[x][y] != -1){
        std::cout<<"Error! That position was not empty!"<<std::endl;
        return -1;
    }

    gameMatrix[x][y] = value;

    for(int i = 0; i < ROWSNUMBER; i++) {
        for (int j = 0; j < COLUMNSNUMBER; j++)
            std::cout << gameMatrix[i][j]<< "  ";
        std::cout<<std::endl;
    }
    return 0;

}

int GameBoard::insertMyMove(uint8_t x, uint8_t y) {

    int ret = insertCoordinateInBoard(x, y, 0);

    if(ret == -1) {
        std::cout<<"Some error occured"<<std::endl;
        return ret;
    }
    //check if I won
    if(gameFinished(0)) {
        std::cout<<"You won"<<std::endl;
        return 1;
    }
    //check if I lost
    if(gameFinished(1)) {
        std::cout<<"You lost"<<std::endl;
        return 2;
    }
    return 0;
}

int GameBoard::insertOpponentMove(uint8_t x, u_int8_t y) {
    int ret = insertCoordinateInBoard(x, y, 1);

    if(ret == -1) {
        std::cout<<"Some error occured"<<std::endl;
        return ret;
    }
    //check if I won
    if(gameFinished(0)) {
        std::cout<<"You won"<<std::endl;
        return 1;
    }
    //check if I lost
    if(gameFinished(1)) {
        std::cout<<"You lost"<<std::endl;
        return 2;
    }
    return 0;
}

bool GameBoard::gameFinished(int valueToCheck) {

    for(int i = 0; i < ROWSNUMBER; i++){    //rows
        for(int j = 0; j < COLUMNSNUMBER; j++){     //colums
                //check horizontal
            if (j + 3 < COLUMNSNUMBER) {
                if (this->gameMatrix[i][j] == valueToCheck &&
                    this->gameMatrix[i][j + 1] == valueToCheck &&
                    this->gameMatrix[i][j + 2] == valueToCheck &&
                    this->gameMatrix[i][j + 3] == valueToCheck) {
                    std::cout<<"HORIZONTAL LINE"<<std::endl;
                    return true;
                }
            }

            // check vertical
            if (i + 3 < ROWSNUMBER) {
                if (this->gameMatrix[i][j] == valueToCheck &&
                    this->gameMatrix[i + 1][j] == valueToCheck &&
                    this->gameMatrix[i + 2][j] == valueToCheck &&
                    this->gameMatrix[i + 3][j] == valueToCheck) {
                    std::cout<<"VERTICAL LINE"<<std::endl;
                    return true;
                }
            }

            //check diagonal from top left corner
            if (i + 3 < ROWSNUMBER && j + 3 < COLUMNSNUMBER) {
                if (this->gameMatrix[i][j] == valueToCheck &&
                    this->gameMatrix[i + 1][j + 1] == valueToCheck &&
                    this->gameMatrix[i + 2][j + 2] == valueToCheck &&
                    this->gameMatrix[i + 3][j + 3] == valueToCheck) {
                    std::cout<<"DIAGONAL FROM TOP LEFT"<<std::endl;
                    return true;
                }
            }

            //check diagonal from top right corner
            if (i + 3 < ROWSNUMBER && j - 3 >= 0) {
                if (this->gameMatrix[i][j] == valueToCheck &&
                    this->gameMatrix[i + 1][j - 1] == valueToCheck &&
                    this->gameMatrix[i + 2][j - 2] == valueToCheck &&
                    this->gameMatrix[i + 3][j - 3] == valueToCheck) {
                    std::cout<<"DIAGONAL FROM TOP RIGHT LINE"<<std::endl;
                    return true;
                }
            }
        }
    }
    return false;
}
