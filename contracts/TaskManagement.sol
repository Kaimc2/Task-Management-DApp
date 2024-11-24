// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TaskManagement {
    struct Task {
        uint taskId;
        string name;
        string description;
        uint priority;
        uint dueDate;
        address assignedTo;
        bool isCompleted;
        uint completedAt;
    }

    uint public taskCounter = 0;
    mapping(uint => Task) public tasks;

    function getTasks() public view returns (Task[] memory) {
        Task[] memory userTasks = new Task[](taskCounter);
        uint index = 0;

        for (uint i = 0; i < taskCounter; i++) 
        {
            if (msg.sender == tasks[i].assignedTo) {
                userTasks[index] = tasks[i];
                index++;
            }
        }

        return userTasks;
    }

    function getTask(uint _taskId) public view returns (Task memory) {
        Task storage task = tasks[_taskId];
        require(msg.sender == task.assignedTo, "Not authorized");

        return task;
    }

    function createTask(
        string memory _name,
        string memory _description,
        uint _priority,
        uint _dueDate,
        address _assignedTo
    ) public {
        tasks[taskCounter] = Task(taskCounter, _name, _description, _priority, _dueDate, _assignedTo, false, 0);
        taskCounter++;
    }

    function completeTask(uint _taskId) public {
        Task storage task = tasks[_taskId];
        require(msg.sender == task.assignedTo, "Not authorized");
        require(!task.isCompleted, "Task already completed");

        task.isCompleted = true;
        task.completedAt = block.timestamp;
    }
}