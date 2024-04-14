numNodes = 2000;
gridSize = 200;
transmissionRange = 30;
simulationDuration = 200;
initialEnergy = 2000;
numEntries = 100;
nodeMobility = 5;

nodePositions = gridSize * rand(numNodes, 2);

sinkholeResults = table('Size', [0, 12], 'VariableNames', {'EntryIndex','Node', 'AttackType', 'TimeStep', 'InitialEnergy', 'EnergyLevel', 'EnergyDrained', 'ActualEnergyConsumed', 'ActualAttackSuccessRate', 'AttackDuration', 'IPS_Prevented', 'IPS_Type'}, 'VariableTypes', {'double','double', 'char', 'double', 'double', 'double', 'double', 'double', 'double', 'double', 'double', 'char'});
ipsTypes = {'Snort', 'Suricata', 'Bro'};
numIpss = numel(ipsTypes);

% Initialize IPS state
ipsStates = struct('Type', ipsTypes, 'Active', true(numIpss, 1));
figure;
scatter(nodePositions(:,1), nodePositions(:,2), 'filled');
title('WSN Topology');
xlabel('X-axis');
ylabel('Y-axis');
axis equal;

energyThreshold = 0.5;  
transmissionCountThreshold = 20; 
ipsTransmissionRange = 25;  
honeypotRange = 40;  
energyIncreaseFactor = 1.5; 
recentAbnormalities = struct('Snort', struct('Count', 0), 'Suricata', struct('Count', 0), 'Bro', struct('Count', 0));
currentNetworkConditions = struct('PacketLoss', 0.1, 'Latency', 20);

for entryIndex = 1:numEntries
    attackNode = randi(numNodes);
    attackType = 'Sinkhole';  
    
    nodePositions = updateNodePositions(nodePositions, nodeMobility);
    
    energyLevels = initializeEnergyLevels(numNodes, initialEnergy);

    attackDuration = randi([10, 50]);
    
    transmissionCount = zeros(1, numNodes);  % Track the number of transmissions
    
    for t = 1:simulationDuration
        disp(['Entry ' num2str(entryIndex) ', Attack Type: ' attackType ', Time Step ' num2str(t)]);
        currentNetworkConditions.PacketLoss = rand() * 0.1;  % Random value between 0 and 0.1
        currentNetworkConditions.Latency = rand() * 50;
        % IPS detection logic
        detectedAbnormalEnergy = detectAbnormalEnergy(energyLevels, energyThreshold);
        detectedAbnormalTransmission = detectAbnormalTransmission(transmissionCount, transmissionCountThreshold);
        bypassIPS = true;

        if detectedAbnormalEnergy || detectedAbnormalTransmission
            disp('Abnormal behavior detected by IPS. Applying preventive measures.');
            activeIpsType = '';
             for ipsIndex = 1:numIpss
                % Check if IPS type is active
                if ipsStates(ipsIndex).Active
                    ipsType = ipsStates(ipsIndex).Type;
                    recentAbnormalities.(ipsType).Count = recentAbnormalities.(ipsType).Count + 1;
                    defaultIpsType = determineDefaultIPS(ipsStates, recentAbnormalities, currentNetworkConditions);
                    disp(defaultIpsType)
                    % Apply IPS to reduce transmission range based on abnormal energy consumption
                    ipsTransmissionRange = calculateIPSTransmissionRange(energyLevels, energyThreshold, defaultIpsType);
                    transmissionRange = min(transmissionRange, ipsTransmissionRange);
                    
                    % You can add more specific IPS actions here

                    % Deactivate IPS type after use (optional, depending on your simulation)
                    activeIpsType = ipsStates(ipsIndex).Type;

                    disp(['IPS Type ' ipsStates(ipsIndex).Type ' applied.']);
                    break;
                     % Stop applying IPS after the first active IPS
                end
            end
             if isempty(activeIpsType)
                % Implement your logic to select a default IPS type or action
                % For example, choose the one with the highest priority
                activeIpsType = determineDefaultIPS(ipsStates);
                disp(['Default IPS Type ' activeIpsType ' applied.']);
            end
            % Allow for some attacks to bypass IPS prevention
            if bypassOne(energyLevels,energyThreshold, transmissionCount, transmissionCountThreshold, numNodes)
                transmissionRange = 30;
            end
        else
            % Reset transmission range
            transmissionRange = 30;

            % Reactivate all IPS types (optional, depending on your simulation)
            ipsStates = struct('Type', ipsTypes, 'Active', true(numIpss, 1));
        end
        
        if t <= attackDuration
            for i = 1:numNodes
                if i == attackNode
                    continue;
                end
                
                if isNodeInRange(nodePositions, i, attackNode, transmissionRange)
                    disp(['Node ' num2str(i) ' transmitted data.']);
                    
                    % IPS prevention logic
                    preventedSinkhole = preventSinkholeAttack(i, nodePositions, attackNode, transmissionRange, energyLevels, energyThreshold);

                    if preventedSinkhole && bypassTwo(energyLevels, transmissionCount, transmissionCountThreshold)
                        disp(['IPS prevented Sinkhole attack from Node ' num2str(i) '.']);
                        % Collect data only for Sinkhole attack
                        activeIpsIndices = find([ipsStates.Active]);  % Find indices of active IPS types
                        if ~isempty(activeIpsIndices)
                            activeIpsType = ipsStates(activeIpsIndices(1)).Type;
                        else
                            activeIpsType = 'No Active IPS';
                        end

                        newRow = createSimulationRow(entryIndex,i, attackType, t, initialEnergy, energyLevels(i), 0, 0, 0, attackDuration, 1, activeIpsType);

                        sinkholeResults = [sinkholeResults; newRow];
                        continue;  % Skip this transmission as it's prevented by IPS
                    end
                    
                    [energyConsumed, energyDrained] = simulateSinkholeEnergyConsumption(initialEnergy, energyLevels(i), transmissionRange, distance(nodePositions(i,:), nodePositions(attackNode,:)), 0);
                    energyLevels(i) = energyLevels(i) - energyConsumed;
                    
                    actualAttackSuccessRate = calculateActualAttackSuccessRate(attackType, energyConsumed);
                    honeypotUsed = useHoneypot(attackNode, nodePositions, honeypotRange);

                    % Collect data only for Sinkhole attack
                    newRow = createSimulationRow(entryIndex, i, attackType, t, initialEnergy, energyLevels(i), energyDrained, energyConsumed, actualAttackSuccessRate, attackDuration, 0, 'No IPS');
                    sinkholeResults = [sinkholeResults; newRow];
                    
                    % Update transmission count for IPS
                    transmissionCount(i) = transmissionCount(i) + 1;
                end
            end
        end
        
        energyLevels = updateEnergyLevels(energyLevels, calculateIdleEnergyConsumption(energyLevels) * energyIncreaseFactor);
    end
end


% Save the Sinkhole attack simulation results
saveSimulationResults(sinkholeResults, 'sinkhole_attack_simulation_results.csv');
calculateAndSaveMetrics(sinkholeResults, numEntries, 'simulation_metrics.csv');

function activeIpsType = determineDefaultIPS(ipsStates, recentAbnormalities, currentNetworkConditions)
    % Implement a more realistic logic to determine the default IPS type

    % Define weights for each factor in the decision-making process
    weightRecentAbnormalities = 2;
    weightNetworkConditions = 1;

    % Initialize variables
    maxScore = -Inf;
    activeIpsType = '';

    % Loop through IPS types and find the one with the highest score
    for ipsIndex = 1:numel(ipsStates)
        if ipsStates(ipsIndex).Active
            ipsType = ipsStates(ipsIndex).Type;

            % Score calculation based on recent abnormalities and network conditions
            score = calculateIpsScore(ipsType, recentAbnormalities, currentNetworkConditions, weightRecentAbnormalities, weightNetworkConditions);

            % Update active IPS type if the current one has a higher score
            if score > maxScore
                maxScore = score;
                activeIpsType = ipsType;
            end
        end
    end

    % If no active IPS type is found, set a default
    if isempty(activeIpsType)
        activeIpsType = 'Snort';  % Default to Snort if none is active
    end
end

function score = calculateIpsScore(ipsType, recentAbnormalities, currentNetworkConditions, weightRecentAbnormalities, weightNetworkConditions)
    % Implement a scoring mechanism based on various factors

    % Example: Calculate a score based on recent abnormalities and network conditions
    % You can customize this based on your specific requirements and data available

    % Get the recent abnormalities for the specific IPS type
    recentAbnormalitiesForIps = recentAbnormalities.(ipsType);

    % Calculate the score using a weighted sum of factors
    score = weightRecentAbnormalities * analyzeRecentAbnormalities(recentAbnormalitiesForIps) + ...
            weightNetworkConditions * analyzeNetworkConditions(currentNetworkConditions);
end

function score = analyzeRecentAbnormalities(recentAbnormalitiesForIps)
    % Real-world logic: Analyze recent abnormalities and return a score

    % Extract relevant information from recent abnormalities
    totalAbnormalities = sum(recentAbnormalitiesForIps.Count);
    maxAbnormalityCount = max(recentAbnormalitiesForIps.Count);
    avgAbnormalityCount = mean(recentAbnormalitiesForIps.Count);

    % Weights for each factor in the overall score
    weightTotalAbnormalities = 0.5;
    weightMaxAbnormalityCount = 0.3;
    weightAvgAbnormalityCount = 0.2;

    % Calculate the score based on a combination of factors
    score = weightTotalAbnormalities * totalAbnormalities + ...
            weightMaxAbnormalityCount * maxAbnormalityCount + ...
            weightAvgAbnormalityCount * avgAbnormalityCount;

    % You can further customize this scoring mechanism based on the specific nature of abnormalities tracked by each IPS type
end


function score = analyzeNetworkConditions(currentNetworkConditions)
    % Real-world logic: Analyze current network conditions and return a score

    % Normalize packet loss between 0 and 1
    normalizedPacketLoss = currentNetworkConditions.PacketLoss / 0.1;  % Assuming 0.1 as a threshold for high packet loss

    % Normalize latency between 0 and 1
    normalizedLatency = currentNetworkConditions.Latency / 50;  % Assuming 50 as a threshold for high latency

    % Calculate the score based on a weighted combination of packet loss and latency
    % Adjust the weights based on the importance of each factor in your context
    weightPacketLoss = 0.7;
    weightLatency = 0.3;

    % Apply a sigmoid function to both normalized values to emphasize extreme conditions
    sigmoid = @(x) 1 / (1 + exp(-x));
    score = weightPacketLoss * sigmoid(10 * (normalizedPacketLoss - 0.5)) + ...
            weightLatency * sigmoid(10 * (normalizedLatency - 0.5));
end





function calculateAndSaveMetrics(simulationResults, numEntries, filename)
    % Initialize variables to store overall metrics
    totalTransmittedPackets = 0;
    totalReceivedPackets = 0;
    totalEnergyConsumption = 0;
    totalDelay = 0;

    % Loop through each entry
    for entryIndex = 1:numEntries
        % Calculate metrics for the current entry
        entryMetrics = calculateEntryMetrics(simulationResults, entryIndex);

        % Accumulate overall metrics
        totalTransmittedPackets = totalTransmittedPackets + entryMetrics.TransmittedPackets;
        totalReceivedPackets = totalReceivedPackets + entryMetrics.ReceivedPackets;
        totalEnergyConsumption = totalEnergyConsumption + entryMetrics.EnergyConsumption;
        totalDelay = totalDelay + entryMetrics.AvgDelay;
    end

    % Calculate overall metrics
    overallMetrics = calculateOverallMetrics(numEntries, totalTransmittedPackets, totalReceivedPackets, totalEnergyConsumption, totalDelay);

    % Save the metrics to a CSV file
    writetable(overallMetrics, filename);
end
function entryMetrics = calculateEntryMetrics(simulationResults, entryIndex)
    % Filter simulationResults for the current entry
    entryResults = simulationResults(simulationResults.EntryIndex == entryIndex, :);

    % Calculate metrics for the current entry
    entryMetrics.TransmittedPackets = height(entryResults);
    entryMetrics.ReceivedPackets = sum(entryResults.ActualAttackSuccessRate > 0);
    entryMetrics.EnergyConsumption = sum(entryResults.ActualEnergyConsumed);
    entryMetrics.AvgDelay = mean(entryResults.TimeStep);
end

function overallMetrics = calculateOverallMetrics(numEntries, totalTransmittedPackets, totalReceivedPackets, totalEnergyConsumption, totalDelay)
    % Calculate aggregated metrics for the entire simulation
    overallMetrics.Throughput = totalReceivedPackets / numEntries;
    overallMetrics.PacketDeliveryRatio = totalReceivedPackets / totalTransmittedPackets;
    overallMetrics.AvgEnergyConsumption = totalEnergyConsumption / totalTransmittedPackets;
    overallMetrics.AvgDelay = totalDelay / totalTransmittedPackets;

    % Create a table to store the metrics
    overallMetrics = struct2table(overallMetrics);
end
%Bypass conditions
function result = bypassOne(energyLevels, energyThreshold, transmissionCount, transmissionCountThreshold, numNodes)
    % Check if a certain percentage of nodes are exhibiting abnormal behavior
    abnormalNodePercentage = sum(energyLevels > (mean(energyLevels) * (1 + energyThreshold))) / numNodes;
    
    % Check if the overall transmission count exceeds a threshold
    highTransmissionCount = any(transmissionCount > transmissionCountThreshold);
    
    % IPS bypass condition: If abnormal nodes are less than 10% and transmission count is not high
    result = abnormalNodePercentage < 0.1 && ~highTransmissionCount;
end

% Function to represent realistic condition for partial IPS prevention
function result =  bypassTwo(energyLevels, transmissionCount, transmissionCountThreshold)
    % Check if there is a sudden spike in energy consumption for any node
    suddenSpike = any(diff(energyLevels) > 100);  % Adjust the threshold as needed
    
    % IPS partial prevention condition: If there is a sudden spike in energy consumption
    result = suddenSpike;
end

function honeypotUsed = useHoneypot(attackNode, nodePositions, honeypotRange)
    % Your logic to determine if honeypot is used
    % For example, check if any node is within honeypotRange of the attackNode
    honeypotUsed = any(distance(nodePositions(attackNode,:), nodePositions) <= honeypotRange);
end
function ipsTransmissionRange = calculateIPSTransmissionRange(energyLevels, energyThreshold, ipsType)
    switch ipsType
        case 'Snort'
            % Snort IPS logic
            % Snort is known for signature-based detection
            detectedAbnormalTraffic = detectAbnormalTrafficSnort(energyLevels, energyThreshold);
            if detectedAbnormalTraffic
                % If abnormal traffic is detected, reduce transmission range
                ipsTransmissionRange = min(energyLevels) * 0.2;
            else
                ipsTransmissionRange = Inf;
            end

        case 'Suricata'
            % Suricata IPS logic
            % Suricata combines signature-based and anomaly-based detection
            detectedAbnormalTraffic = detectAbnormalTrafficSuricata(energyLevels, energyThreshold);
            if detectedAbnormalTraffic
                % If abnormal traffic is detected, reduce transmission range
                ipsTransmissionRange = min(energyLevels) * 0.3;
            else
                ipsTransmissionRange = Inf;
            end

        case 'Bro'
            % Bro (Zeek) IPS logic
            % Bro focuses on network traffic analysis
            detectedAbnormalTraffic = detectAbnormalTrafficBro(energyLevels, energyThreshold);
            if detectedAbnormalTraffic
                % If abnormal traffic is detected, reduce transmission range
                ipsTransmissionRange = min(energyLevels) * 0.25;
            else
                ipsTransmissionRange = Inf;
            end

        otherwise
            error('Unsupported IPS type');
    end
end

function detectedAbnormalTraffic = detectAbnormalTrafficSnort(energyLevels, energyThreshold)
    % Example Snort detection logic
    % This is a simplified signature-based detection
    % In a real-world scenario, Snort rules would be used
    % For simplicity, let's assume abnormal traffic if any node has high energy consumption
    detectedAbnormalTraffic = any(energyLevels > (mean(energyLevels) * (1 + energyThreshold)));
end

function detectedAbnormalTraffic = detectAbnormalTrafficSuricata(energyLevels, energyThreshold)
    % Example Suricata detection logic
    % This is a simplified combination of signature-based and anomaly-based detection
    % In a real-world scenario, Suricata rules and anomaly detection algorithms would be used
    % For simplicity, let's assume abnormal traffic if any node has high energy consumption
    detectedAbnormalTraffic = any(energyLevels > (mean(energyLevels) * (1 + energyThreshold)));
end

function detectedAbnormalTraffic = detectAbnormalTrafficBro(energyLevels, energyThreshold)
    % Example Bro (Zeek) detection logic
    % This is a simplified network traffic analysis logic
    % In a real-world scenario, Bro scripts and analysis would be used
    % For simplicity, let's assume abnormal traffic if any node has high energy consumption
    detectedAbnormalTraffic = any(energyLevels > (mean(energyLevels) * (1 + energyThreshold)));
end


function detectedAbnormalEnergy = detectAbnormalEnergy(energyLevels, energyThreshold)
    % IPS logic: Detect abnormal energy consumption
    detectedAbnormalEnergy = any(energyLevels > (mean(energyLevels) * (1 + energyThreshold)));
end

function detectedAbnormalTransmission = detectAbnormalTransmission(transmissionCount, transmissionCountThreshold)
    % IPS logic: Detect abnormal transmission count
    detectedAbnormalTransmission = any(transmissionCount > transmissionCountThreshold);
end

function detectedSinkhole = detectSinkholeAttack(energyLevels, transmissionCount, energyThreshold, transmissionCountThreshold)
    % IDS logic: Detect Sinkhole based on abnormal energy consumption and transmission count
    averageEnergyConsumption = mean(energyLevels);
    energyConsumptionThreshold = averageEnergyConsumption * (1 + energyThreshold);
    
    % Check if any node has abnormal energy consumption or transmission count
    detectedSinkhole = any(energyLevels > energyConsumptionThreshold) || any(transmissionCount > transmissionCountThreshold);
end

function preventedSinkhole = preventSinkholeAttack(node, nodePositions, attackNode, transmissionRange, energyLevels, energyThreshold)
    % IPS logic: Prevent Sinkhole by checking if the attacker is in range
        preventedSinkhole = isNodeInRange(nodePositions, node, attackNode, transmissionRange) && (energyLevels(node) > energyThreshold);
 
end

% The rest of the functions remain unchanged.


function [energyConsumed, energyDrained] = simulateSinkholeEnergyConsumption(initialEnergy, currentEnergy, transmissionRange, distanceToAttackNode, packetsIntercepted)
    transmissionLoss = exp(-distanceToAttackNode / transmissionRange);
    
    % Customize the energy consumption for Sinkhole attack
    interceptedFactor = 1 + 0.1 * packetsIntercepted; % Adjust the factor based on intercepted packets
    energyConsumed = min(currentEnergy, initialEnergy * (1 - transmissionLoss) * interceptedFactor) * 0.9;  % Default factor for Sinkhole
    energyDrained = currentEnergy - (currentEnergy - energyConsumed);
end


function idleEnergyConsumption = calculateIdleEnergyConsumption(energyLevels)
    idleEnergyConsumption = mean(energyLevels) * 0.002;
end

function actualAttackSuccessRate = calculateActualAttackSuccessRate(attackType, energyConsumed)
    actualAttackSuccessRate = 1 - exp(-energyConsumed / 100);
end


function inRange = isNodeInRange(nodePositions, node1, node2, range)
    inRange = distance(nodePositions(node1,:), nodePositions(node2,:)) <= range;
end

function updatedPositions = updateNodePositions(nodePositions, mobility)
    updatedPositions = nodePositions + mobility * randn(size(nodePositions));
end

function energyLevels = initializeEnergyLevels(numNodes, initialEnergy)
    energyLevels = ones(1, numNodes) * initialEnergy;
end

function updatedEnergyLevels = updateEnergyLevels(energyLevels, idleEnergyConsumption)
    updatedEnergyLevels = energyLevels - idleEnergyConsumption;
end

function newRow = createSimulationRow(entryIndex,node, attackType, timeStep, initialEnergy, energyLevel, energyDrained, energyConsumed, attackSuccessRate, attackDuration, ipsPrevented, ipsUsed)
    newRow = {entryIndex,node, attackType, timeStep, initialEnergy, energyLevel, energyDrained, energyConsumed, attackSuccessRate, attackDuration, ipsPrevented, ipsUsed};
end


function d = distance(p1, p2)
    d = sqrt(sum((p1 - p2).^2));
end

function saveSimulationResults(simulationResults, filename)
    randomFilename = fullfile(['simulation_results_' num2str(randi(1000)) '.csv']);
    writetable(simulationResults, randomFilename, 'WriteRowNames', false);
end
